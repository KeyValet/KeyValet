#[cfg(unix)]
mod native {
    //! Live-relay software executor for physical phone acceptance. Never accesses a real vault.
    use futures_util::{SinkExt, StreamExt};
    use kv_core::remote::{
        canonical::{from_json, jcs, sha256_hex, CanonicalRequest},
        keys::{decode_b64, encode_b64},
        *,
    };
    use rand_core::RngCore;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::BufRead,
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio_tungstenite::{
        tungstenite::{client::IntoClientRequest, Message},
        MaybeTlsStream, WebSocketStream,
    };
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
    const RELAY: &str = "https://relay.keyvalet.dev/";
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
    fn now_ms() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }
    fn id() -> String {
        let mut bytes = [0; 16];
        rand_core::OsRng.fill_bytes(&mut bytes);
        bytes[..6].copy_from_slice(&((now() as u64) * 1000).to_be_bytes()[2..]);
        let mut number = u128::from_be_bytes(bytes);
        let mut text = [b'0'; 26];
        for byte in text.iter_mut().rev() {
            *byte = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[(number & 31) as usize];
            number >>= 5;
        }
        String::from_utf8(text.to_vec()).unwrap()
    }
    #[derive(Serialize, Deserialize)]
    struct Pending {
        request: ApprovalRequest,
        canonical: CanonicalRequest,
        escalated: bool,
        started: i64,
    }
    #[derive(Serialize, Deserialize)]
    struct Disk {
        own: DeviceRecord,
        account: String,
        peer: Option<DeviceRecord>,
        paired: bool,
        pair_id: String,
        pair_token: Vec<u8>,
        sas: String,
        pair_exp: i64,
        local_confirmed: bool,
        pending: BTreeMap<String, Pending>,
        consumed: BTreeSet<String>,
        executions: u64,
        grants: BTreeMap<String, Grant>,
        mode: String,
    }
    struct Consumed<'a>(&'a mut BTreeSet<String>);
    impl validation::NonceStore for Consumed<'_> {
        fn consume(&mut self, nonce: &str, _: &str, _: i64) -> kv_core::remote::Result<()> {
            if self.0.insert(nonce.into()) {
                Ok(())
            } else {
                Err(RemoteError::Replay)
            }
        }
    }
    struct Fixture {
        key: Arc<SoftwareDeviceKey>,
        data: Disk,
        directory: PathBuf,
        http: reqwest::Client,
        token: String,
    }
    impl Fixture {
        fn save(&self) -> Result<()> {
            use std::os::unix::fs::OpenOptionsExt;
            let path = self.directory.join("fixture.json");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            std::io::Write::write_all(&mut file, &serde_json::to_vec(&self.data)?)?;
            Ok(())
        }
        async fn post(&self, path: &str, body: Value, auth: bool) -> Result<Value> {
            let mut request = self.http.post(format!("{RELAY}{path}")).json(&body);
            if auth {
                request = request.header("authorization", format!("Device {}", self.token));
            }
            let response = request.send().await?;
            if !response.status().is_success() {
                return Err(format!("relay returned {} for {path}", response.status()).into());
            }
            Ok(response.json().await?)
        }
        async fn login(&mut self) -> Result<()> {
            let challenge = self
                .post(
                    "v1/auth/challenge",
                    json!({"device_id":self.data.own.device_id}),
                    false,
                )
                .await?;
            let signature = DeviceKeyProvider::sign(
                self.key.as_ref(),
                SignatureAlgorithm::ES256,
                &decode_b64(challenge["challenge"].as_str().ok_or("missing challenge")?)?,
            )?;
            let response=self.post("v1/auth/verify",json!({"device_id":self.data.own.device_id,"challenge":challenge["challenge"],"sig":encode_b64(&signature)}),false).await?;
            self.token = response["session_token"]
                .as_str()
                .ok_or("missing session")?
                .into();
            Ok(())
        }
        async fn socket(&mut self) -> Result<Socket> {
            self.login().await?;
            let mut request = "wss://relay.keyvalet.dev/v1/presence".into_client_request()?;
            request
                .headers_mut()
                .insert("authorization", format!("Device {}", self.token).parse()?);
            request
                .headers_mut()
                .insert("sec-websocket-protocol", "kv-relay-v1".parse()?);
            Ok(tokio_tungstenite::connect_async(request).await?.0)
        }
        fn seal<T: Serialize>(
            &self,
            kind: EnvelopeType,
            id: &str,
            payload: &T,
            exp: i64,
            mode: Option<DeliveryMode>,
            created: i64,
        ) -> Result<Envelope> {
            let peer = self
                .data
                .peer
                .as_ref()
                .ok_or("scan the pairing code first")?;
            let mut extra = Extra::new();
            if let Some(mode) = mode {
                extra.insert("push".into(), json!({"mode":mode}));
            }
            Ok(envelope::seal(
                EnvelopeHeader {
                    v: 1,
                    r#type: kind,
                    id: id.into(),
                    account: self.data.account.clone(),
                    from: self.data.own.device_id.clone(),
                    to: peer.device_id.clone(),
                    created_at: created,
                    exp,
                    extra,
                },
                &jcs(payload)?,
                &peer.dk_pub,
                self.key.as_ref(),
            )?)
        }
        async fn messages(&self, envelope: Envelope) -> Result<()> {
            self.post("v1/messages", json!({"envelopes":[envelope]}), true)
                .await?;
            Ok(())
        }
        async fn pair(&mut self) -> Result<()> {
            rand_core::OsRng.fill_bytes(&mut self.data.pair_token);
            self.data.pair_exp = now() + 600;
            self.data.local_confirmed = false;
            self.data.paired = false;
            let response=self.post("v1/pair/start",json!({"token_hash":sha256_hex(&self.data.pair_token),"initiator":self.data.own,"exp":self.data.pair_exp}),true).await?;
            self.data.pair_id = response["pairing_id"]
                .as_str()
                .ok_or("missing pairing id")?
                .into();
            let mut encoded = String::new();
            let mut bits = 0_u32;
            let mut count = 0;
            for byte in &self.data.pair_token {
                bits = (bits << 8) | u32::from(*byte);
                count += 8;
                while count >= 5 {
                    count -= 5;
                    encoded.push(
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[((bits >> count) & 31) as usize]
                            as char,
                    );
                }
            }
            if count > 0 {
                encoded.push(
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[((bits << (5 - count)) & 31) as usize]
                        as char,
                );
            }
            println!("pair_uri=kv-pair://relay.keyvalet.dev/{encoded}");
            self.save()
        }
        async fn confirm(&mut self, sas: &str) -> Result<()> {
            if sas != self.data.sas || self.data.peer.is_none() {
                return Err("compare both SAS displays".into());
            }
            let confirm = PairConfirm {
                sas: sas.into(),
                sig: String::new(),
                extra: json!({"device":self.data.own,"exclude_global":false})
                    .as_object()
                    .unwrap()
                    .clone(),
            };
            self.messages(self.seal(
                EnvelopeType::PairConfirm,
                &self.data.pair_id,
                &confirm,
                self.data.pair_exp,
                None,
                now(),
            )?)
            .await?;
            self.post(
                "v1/pair/finish",
                json!({"pairing_id":self.data.pair_id,"confirm":confirm}),
                true,
            )
            .await?;
            self.data.local_confirmed = true;
            self.save()?;
            println!("event=executor_sas_confirmed");
            Ok(())
        }
        async fn request(
            &mut self,
            tier: &str,
            mode: &str,
            offset: i64,
            label: &str,
        ) -> Result<()> {
            if !self.data.paired {
                return Err("finish both SAS confirmations first".into());
            }
            let tier: Tier = serde_json::from_value(tier.into())?;
            let mode: DeliveryMode = serde_json::from_value(mode.into())?;
            let mut nonce = [0_u8; 16];
            rand_core::OsRng.fill_bytes(&mut nonce);
            let exp = now() + 600;
            // Only synthetic operation metadata; no credential value, real API request or real execution.
            let canonical: CanonicalRequest = serde_json::from_value(
                json!({"v":1,"kind":"use","requester":self.data.own.device_id,
            "credential":"fixture/r2c","action":{"kind":"http"},"method":"GET","host":"example.com","path":"/r2c", "query_keys":[],
            "body_sha256":null,"headers_digest":null,"agent":{"runtime":"codex","repo_or_cwd":"/tmp/r2c-fixture","uid":501,"pid":42,"exe_sha256":"0".repeat(64)},
            "purpose":"Verify the physical phone approval path","nonce":encode_b64(&nonce),"exp":exp}),
            )?;
            let description = if tier == Tier::T2 {
                "Verify Strong approval (fixture)"
            } else {
                "Read test result (fixture)"
            };
            let summary = if label.is_empty() {
                description.to_owned()
            } else {
                format!("R2-C {label}: {description}")
            };
            let request: ApprovalRequest = serde_json::from_value(
                json!({"approval_id":id(),"kind":"use","digest":canonical.digest()?,"nonce":canonical.nonce,"exp":exp,
            "requester":{"device_id":self.data.own.device_id,"label":self.data.own.label,"os":"macos","protection":{"kind":"software_key"}},
            "agent":{"runtime":"codex","cwd":"/tmp/r2c-fixture","user":"fixture","pid":42},
            "credential":{"ref":"fixture/r2c","kind":"static","display":"R2-C test credential","proxy_only":true},
            "operation":{"summary":summary,"method":"GET","host":"example.com","path":"/r2c","query_keys":[],"body_bytes":0},
            "purpose":canonical.purpose,"tier":tier,"min_level":if tier==Tier::T2 {"strong"}else{"quick"},"scope_options":["per_use"],"requested_scope":"per_use","merged_count":1,
            "delivery":{"mode":mode,"escalate_after_s":30}}),
            )?;
            let envelope = self.seal(
                EnvelopeType::ApprovalRequest,
                &request.approval_id,
                &request,
                exp,
                Some(mode),
                now() + offset,
            )?;
            self.post(
                "v1/approvals",
                json!({"id":request.approval_id,"exp":exp,"envelopes":[envelope]}),
                true,
            )
            .await?;
            println!(
                "event=request id={} tier={tier:?} mode={mode:?} at={}",
                request.approval_id,
                now()
            );
            self.data.pending.insert(
                request.approval_id.clone(),
                Pending {
                    request,
                    canonical,
                    escalated: mode == DeliveryMode::Banner,
                    started: now(),
                },
            );
            self.save()
        }
        async fn tick(&mut self) -> Result<()> {
            let ids = self
                .data
                .pending
                .iter()
                .filter(|(_, p)| !p.escalated && now() >= p.started + 30 && p.request.exp > now())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            for id in ids {
                let pending = &self.data.pending[&id];
                let envelope = self.seal(
                    EnvelopeType::ApprovalEscalate,
                    &id,
                    &json!({"approval_id":id,"reason":"no_response"}),
                    pending.request.exp,
                    Some(DeliveryMode::Banner),
                    now(),
                )?;
                self.post(
                    "v1/approvals",
                    json!({"id":id,"exp":pending.request.exp,"envelopes":[envelope]}),
                    true,
                )
                .await?;
                self.data.pending.get_mut(&id).unwrap().escalated = true;
                println!(
                    "event=escalate id={id} elapsed_s={}",
                    now() - self.data.pending[&id].started
                );
                self.save()?;
            }
            Ok(())
        }
        async fn incoming(&mut self, envelope: Envelope) -> Result<()> {
            let peer = self.data.peer.clone().ok_or("missing peer")?;
            let plaintext = envelope::open(
                &envelope,
                &self.data.own.device_id,
                self.key.as_ref(),
                &peer,
                now(),
            )?;
            match envelope.r#type {
                EnvelopeType::PairAccept => {
                    let accept: PairAccept = from_json(&plaintext)?;
                    if decode_b64(&accept.token)? != self.data.pair_token
                        || !validation::same_device_authority(&peer, &accept.joiner)
                    {
                        return Err("pair binding mismatch".into());
                    }
                    self.data.sas =
                        pairing::device_sas(&self.data.pair_token, &self.data.own, &peer)?;
                    println!("event=scan_received sas={}", self.data.sas);
                }
                EnvelopeType::PairConfirm => {
                    let confirm: PairConfirm = from_json(&plaintext)?;
                    pairing::verify_confirm(
                        &confirm,
                        &self.data.sas,
                        peer.ak_s.as_ref().ok_or("Strong key required")?,
                    )?;
                    if !self.data.local_confirmed {
                        return Err("confirm executor SAS first".into());
                    }
                    self.data.paired = true;
                    println!("event=paired hardware_phone=true");
                }
                EnvelopeType::ApprovalDecision => {
                    let decision: ApprovalDecision = from_json(&plaintext)?;
                    let pending = self
                        .data
                        .pending
                        .get(&decision.approval_id)
                        .ok_or("unknown decision")?;
                    validation::verify_and_consume_decision(
                        &decision,
                        &pending.request,
                        &pending.canonical,
                        &peer,
                        now(),
                        &mut Consumed(&mut self.data.consumed),
                    )?;
                    let replay = validation::verify_and_consume_decision(
                        &decision,
                        &pending.request,
                        &pending.canonical,
                        &peer,
                        now(),
                        &mut Consumed(&mut self.data.consumed),
                    );
                    if !matches!(replay, Err(RemoteError::Replay)) {
                        return Err("second consumption unexpectedly accepted".into());
                    }
                    if decision.decision == Decision::Allow {
                        self.data.executions += 1;
                    }
                    println!("event=decision id={} level={:?} decision={:?} executions={} second_claim=Replay elapsed_s={}",decision.approval_id,decision.level,decision.decision,self.data.executions,now()-pending.started);
                    let cancellation = self.seal(
                        EnvelopeType::ApprovalCancel,
                        &decision.approval_id,
                        &json!({"approval_id":decision.approval_id}),
                        now() + 120,
                        Some(DeliveryMode::Silent),
                        now(),
                    )?;
                    self.post(
                        &format!("v1/approvals/{}/cancel", decision.approval_id),
                        json!({"envelope":cancellation}),
                        true,
                    )
                    .await?;
                    self.data.pending.remove(&decision.approval_id);
                }
                EnvelopeType::Grant => {
                    let grant: Grant = from_json(&plaintext)?;
                    validation::verify_grant(
                        &grant,
                        &self.data.own.device_id,
                        &self.data.own.label,
                        &peer,
                        ApprovalLevel::Strong,
                        now(),
                    )?;
                    println!(
                        "event=grant hours={} signature=Strong at_ms={}",
                        grant.exp.map(|exp| (exp - now()) / 3600).unwrap_or(-1),
                        now_ms()
                    );
                    self.data.grants.insert(grant.jti.clone(), grant);
                }
                EnvelopeType::Directive => {
                    let directive: Directive = from_json(&plaintext)?;
                    let state = validation::DirectiveState {
                        mode: Some(self.data.mode.clone()),
                        unlock_ttl_s: Some(3600),
                        classes: Default::default(),
                    };
                    let verify = |level| {
                        validation::verify_directive(
                            &directive,
                            &self.data.own.device_id,
                            &peer,
                            level,
                            now(),
                            &state,
                        )
                    };
                    verify(ApprovalLevel::Quick).or_else(|_| verify(ApprovalLevel::Strong))?;
                    if !self.data.consumed.insert(directive.nonce.clone()) {
                        return Err("directive replay".into());
                    }
                    match directive.op {
                        DirectiveOp::SetMode => {
                            self.data.mode = directive.args["mode"]
                                .as_str()
                                .ok_or("missing mode")?
                                .into()
                        }
                        DirectiveOp::RevokeAllGrants => self.data.grants.clear(),
                        DirectiveOp::RevokeGrant => {
                            self.data
                                .grants
                                .remove(directive.args["jti"].as_str().unwrap_or(""));
                        }
                        _ => {}
                    }
                    let grants = self
                        .data
                        .grants
                        .values()
                        .map(|grant| {
                            let mut value = serde_json::to_value(grant).unwrap();
                            value["revoked_at"] = Value::Null;
                            value
                        })
                        .collect::<Vec<_>>();
                    let response=DirectiveResult {id:directive.id.clone(),ok:true,error:None,state:json!({"mode":self.data.mode,"unlock_ttl_s":3600,"unattended":false,"unattended_t2":0,"grants":grants,"entries":[]}).as_object().unwrap().clone(),extra:Extra::new()};
                    self.messages(self.seal(
                        EnvelopeType::DirectiveResult,
                        &directive.id,
                        &response,
                        now() + 120,
                        Some(DeliveryMode::Silent),
                        now(),
                    )?)
                    .await?;
                    println!(
                        "event=directive op={:?} mode={} grants={} at_ms={}",
                        directive.op,
                        self.data.mode,
                        self.data.grants.len(),
                        now_ms()
                    );
                }
                _ => {}
            }
            self.save()?;
            self.post(
                "v1/messages/ack",
                json!({"ids":[envelope.id],"type":envelope.r#type.as_str()}),
                true,
            )
            .await?;
            Ok(())
        }
    }
    #[tokio::main]
    pub async fn run() -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = PathBuf::from(
            std::env::args()
                .nth(1)
                .ok_or("usage: r2c_phone_fixture <private state directory>")?,
        );
        std::fs::create_dir_all(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let key_path = directory.join("software-dk");
        let key = if key_path.exists() {
            SoftwareDeviceKey::from_p256_bytes(&std::fs::read(&key_path)?)?
        } else {
            let (key, bytes) = SoftwareDeviceKey::generate_p256_material();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)?;
            std::io::Write::write_all(&mut file, bytes.as_ref())?;
            key
        };
        let data = if directory.join("fixture.json").exists() {
            serde_json::from_slice(&std::fs::read(directory.join("fixture.json"))?)?
        } else {
            Disk {
                own: DeviceRecord {
                    device_id: format!("dev_{}", id()),
                    label: "R2-C software Mac fixture".into(),
                    os: Os::Macos,
                    key_kind: KeyKind::Software,
                    dk_pub: key.public_jwk()?,
                    dk_sig: Optional::Missing,
                    ak_q: None,
                    ak_s: None,
                    caps: vec![Capability::Execute],
                    attestation: None,
                    extra: Extra::new(),
                },
                account: String::new(),
                peer: None,
                paired: false,
                pair_id: String::new(),
                pair_token: vec![0; 16],
                sas: String::new(),
                pair_exp: 0,
                local_confirmed: false,
                pending: BTreeMap::new(),
                consumed: BTreeSet::new(),
                executions: 0,
                grants: BTreeMap::new(),
                mode: "per_use".into(),
            }
        };
        let mut fixture = Fixture {
            key: Arc::new(key),
            data,
            directory,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(12))
                .build()?,
            token: String::new(),
        };
        if fixture.data.account.is_empty() {
            let response = fixture
                .post(
                    "v1/devices",
                    serde_json::to_value(&fixture.data.own)?,
                    false,
                )
                .await?;
            fixture.data.account = response["account_id"]
                .as_str()
                .ok_or("missing account")?
                .into();
            fixture.save()?;
        }
        let mut socket = fixture.socket().await?;
        println!("event=ready software_executor=true commands=pair,confirm,request,status,quit");
        let (sender, mut commands) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in std::io::stdin()
                .lock()
                .lines()
                .map_while(std::result::Result::ok)
            {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                command=commands.recv()=>{let Some(command)=command else {break;};let parts=command.split_whitespace().collect::<Vec<_>>();
                    let result=match parts.as_slice() {
                        ["pair"]=>fixture.pair().await,["confirm",sas]=>fixture.confirm(sas).await,
                        ["request",tier,mode]=>fixture.request(tier,mode,0, "").await,
                        ["request",tier,mode,label]=>fixture.request(tier,mode,0, label).await,
                        ["skew",offset]=>fixture.request("T1","banner",offset.parse()?, &format!("CLOCK-{offset}")).await,
                        ["status"]=>{println!("event=status paired={} pending={} executions={} mode={} grants={}",fixture.data.paired,fixture.data.pending.len(),fixture.data.executions,fixture.data.mode,fixture.data.grants.len());Ok(())},
                        ["quit"]=>break,_=>Err("unknown command".into())};
                    if let Err(error)=result {println!("event=command_error reason={error}");}
                },
                _=timer.tick()=>{if let Err(error)=fixture.tick().await {println!("event=tick_error reason={error}");}},
                _=heartbeat.tick()=>{socket.send(Message::Text("{\"t\":\"ping\"}".into())).await?;},
                message=socket.next()=>{match message {
                    Some(Ok(Message::Text(text)))=>{let frame:Value=from_json(text.as_bytes())?;
                        if frame["t"]=="pair_accept" {fixture.data.peer=Some(serde_json::from_value(frame["joiner"].clone())?);fixture.save()?;}
                        else if frame["t"]=="envelope" {let envelope:Envelope=serde_json::from_value(frame["envelope"].clone())?;
                            if let Err(error)=fixture.incoming(envelope).await {println!("event=inbound_error reason={error}");}}
                    },Some(Ok(Message::Ping(bytes)))=>socket.send(Message::Pong(bytes)).await?,
                    Some(Ok(Message::Pong(_)))=>{},_=>{println!("event=reconnect");socket=fixture.socket().await?;}
                }}
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    native::run()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("The phone acceptance fixture requires a Unix host.");
    std::process::exit(2);
}
