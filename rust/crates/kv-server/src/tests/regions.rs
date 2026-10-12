use super::*;
use crate::error::{ApiError, Result};
use crate::http::Wire;
use axum::extract::{ConnectInfo, OriginalUri, Path, State};
use axum::http::HeaderMap;
use kv_core::remote::relay::ErrorCode;
use rusqlite::hooks::{AuthContext, Authorization};
use rusqlite::params;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FastPasswords;

impl auth::RecoveryPasswords for FastPasswords {
    fn hash(&self, _: &str) -> Result<String> {
        Ok("test-only-password-hash".into())
    }

    fn verify(&self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Register,
    Challenge,
    Verify,
    PairStart,
    PairComplete,
    PairMigrate,
    PairFinish,
    PairMismatch,
    PairMessages,
    Messages,
    Submit,
    Escalate,
    Reply,
    Cancel,
    Waiting,
    Ack,
    RevokeRecovery,
    RevokeStrong,
    Cleanup,
}

struct Case {
    operation: Operation,
    state: Arc<state::State>,
    headers: HeaderMap,
    body: Value,
    id: String,
}

fn device_headers(device: &Device) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Device {}", device.token).parse().unwrap(),
    );
    headers
}

impl Case {
    fn new(operation: Operation) -> Self {
        let mut relay = state::State::new(Connection::open_in_memory().unwrap(), true).unwrap();
        Arc::get_mut(&mut relay).unwrap().recovery = Arc::new(FastPasswords);
        let mut requester = Device::new("fault_requester", false);
        let mut approver = Device::new("fault_approver", true);
        let mut other = Device::new("fault_other", true);
        let mut joining = Device::new("fault_joining", true);
        let timestamp = relay.now();
        for device in [&mut requester, &mut approver, &mut other] {
            device.account = "acct_fault_fixture".into();
            device.token = state::random_token(32);
        }
        joining.account = "acct_singleton".into();
        joining.token = state::random_token(32);
        let id = state::ulid(timestamp);
        let pairing_id = state::ulid(timestamp);
        let pair_token = [3; 16];
        let challenge = encode_b64(&[5; 32]);
        let exp = timestamp + 300;
        relay.with(|data, _| {
            data.db.execute("INSERT INTO accounts(id,created_at,recovery_hash) VALUES(?1,?2,'test-only-password-hash')",
                params![requester.account, timestamp])?;
            for device in [&requester, &approver, &other] {
                state::insert_device(&data.db, &device.account, &device.record, None, timestamp)?;
                data.db.execute("INSERT INTO sessions(token_hash,device_id,exp) VALUES(?1,?2,?3)",
                    params![sha256_hex(device.token.as_bytes()), device.record.device_id, timestamp + state::SESSION_TTL])?;
            }
            data.db.execute("INSERT INTO approvals(id,account_id,requester,state,exp) VALUES(?1,?2,?3,'waiting',?4)",
                params![id, requester.account, requester.record.device_id, exp])?;
            for recipient in [&approver, &other] {
                let envelope = requester.seal(recipient, &id, EnvelopeType::ApprovalRequest, exp, &json!({"private":"fault-regression-payload"}));
                data.db.execute("INSERT INTO messages(id,account_id,from_device,to_device,type,envelope,created_at,exp) VALUES(?1,?2,?3,?4,'approval_request',?5,?6,?7)",
                    params![id, requester.account, requester.record.device_id, recipient.record.device_id, serde_json::to_vec(&envelope).unwrap(), timestamp, exp])?;
            }
            let accepted = matches!(operation, Operation::PairFinish | Operation::PairMismatch | Operation::PairMessages | Operation::Cleanup);
            data.db.execute("INSERT INTO pairings(pairing_id,token_hash,account_id,initiator_device,initiator_pubs,joiner_device,joiner_pubs,state,exp,sas_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![pairing_id, sha256_hex(&pair_token), requester.account, requester.record.device_id, serde_json::to_vec(&requester.record).unwrap(),
                    accepted.then_some(&approver.record.device_id), accepted.then(|| serde_json::to_vec(&approver.record).unwrap()),
                    if accepted { "accepted" } else { "offered" }, exp,
                    (operation == Operation::PairMismatch).then(|| sha256_hex(b"654321"))])?;
            data.db.execute("INSERT INTO used_pair_tokens(token_hash,exp) VALUES(?1,?2)", params![sha256_hex(&pair_token), exp])?;
            if operation == Operation::PairMigrate {
                data.db.execute("INSERT INTO accounts(id,created_at,recovery_hash) VALUES(?1,?2,'test-only-password-hash')", params![joining.account, timestamp])?;
                state::insert_device(&data.db, &joining.account, &joining.record, None, timestamp)?;
                data.db.execute("INSERT INTO sessions(token_hash,device_id,exp) VALUES(?1,?2,?3)",
                    params![sha256_hex(joining.token.as_bytes()), joining.record.device_id, timestamp + state::SESSION_TTL])?;
            }
            let challenged = if operation == Operation::RevokeStrong { &approver } else { &requester };
            data.challenges.insert(challenged.record.device_id.clone(), state::Challenge {
                hash: sha256_hex(challenge.as_bytes()), exp,
            });
            Ok(())
        }).unwrap();
        let mut headers = device_headers(match operation {
            Operation::Reply | Operation::Waiting | Operation::Ack | Operation::RevokeStrong => {
                &approver
            }
            Operation::PairMigrate => &joining,
            _ => &requester,
        });
        let body = match operation {
            Operation::Register => serde_json::to_value(&joining.record).unwrap(),
            Operation::Challenge => json!({"device_id":requester.record.device_id}),
            Operation::Verify => {
                json!({"device_id":requester.record.device_id,"challenge":challenge,
                "sig":encode_b64(&requester.dk.sign(SignatureAlgorithm::ES256, &[5;32]).unwrap())})
            }
            Operation::PairStart => {
                json!({"token_hash":sha256_hex(&[6;16]),"initiator":requester.record,"exp":exp})
            }
            Operation::PairComplete | Operation::PairMigrate => {
                json!({"token":encode_b64(&pair_token),"joiner":joining.record})
            }
            Operation::PairFinish => {
                json!({"pairing_id":pairing_id,"confirm":requester.confirm("123456")})
            }
            Operation::PairMismatch => {
                json!({"pairing_id":pairing_id,"confirm":requester.confirm("123456")})
            }
            Operation::Messages | Operation::PairMessages => {
                json!({"envelopes":[requester.seal(&approver, &state::ulid(timestamp),
                if operation == Operation::PairMessages { EnvelopeType::PairConfirm } else { EnvelopeType::Grant }, exp, &json!({"private":"fault-regression-payload"}))]})
            }
            Operation::Submit => {
                let new_id = state::ulid(timestamp);
                json!({"id":new_id,"exp":exp,"envelopes":[requester.seal(&approver, &new_id, EnvelopeType::ApprovalRequest, exp, &json!({"private":"fault-regression-payload"}))]})
            }
            Operation::Escalate => {
                json!({"id":id,"exp":exp,"envelopes":[requester.seal(&approver, &id, EnvelopeType::ApprovalEscalate, exp, &json!({"private":"fault-regression-payload"}))]})
            }
            Operation::Reply => {
                json!({"envelope":approver.seal(&requester, &id, EnvelopeType::ApprovalDecision, exp, &json!({"private":"fault-regression-payload"}))})
            }
            Operation::Cancel | Operation::Waiting | Operation::Cleanup => json!({}),
            Operation::Ack => json!({"ids":[id]}),
            Operation::RevokeRecovery => json!({"by":"recovery","recovery_code":"test-only-code"}),
            Operation::RevokeStrong => {
                let proof = jcs(&json!({"action":"revoke_device","account":requester.account,
                    "by":approver.record.device_id,"device_id":requester.record.device_id,"challenge":challenge})).unwrap();
                headers.insert("x-kv-challenge", challenge.parse().unwrap());
                headers.insert(
                    "x-kv-strong-signature",
                    encode_b64(
                        &approver
                            .strong
                            .as_ref()
                            .unwrap()
                            .sign(SignatureAlgorithm::ES256, &proof)
                            .unwrap(),
                    )
                    .parse()
                    .unwrap(),
                );
                json!({"by":"device"})
            }
        };
        let id = if matches!(
            operation,
            Operation::RevokeRecovery | Operation::RevokeStrong
        ) {
            requester.record.device_id.clone()
        } else {
            id
        };
        if operation == Operation::Cleanup {
            relay.advance(400);
        }
        Self {
            operation,
            state: relay,
            headers,
            body,
            id,
        }
    }

    fn copy_state(&self) -> Arc<state::State> {
        copy_state(&self.state)
    }

    fn request<T: serde::de::DeserializeOwned>(&self) -> Wire<T> {
        Wire(
            kv_core::remote::canonical::from_json(&serde_json::to_vec(&self.body).unwrap())
                .unwrap(),
        )
    }

    async fn run(&self, state: Arc<state::State>) -> Result<()> {
        let peer = ConnectInfo("127.0.0.1:9000".parse().unwrap());
        let headers = self.headers.clone();
        match self.operation {
            Operation::Register => auth::register(State(state), peer, headers, self.request())
                .await
                .map(|_| ()),
            Operation::Challenge => auth::challenge(State(state), peer, headers, self.request())
                .await
                .map(|_| ()),
            Operation::Verify => auth::verify(State(state), peer, headers, self.request())
                .await
                .map(|_| ()),
            Operation::PairStart => crate::pairing::start(State(state), headers, self.request())
                .await
                .map(|_| ()),
            Operation::PairComplete | Operation::PairMigrate => {
                crate::pairing::complete(State(state), peer, headers, self.request())
                    .await
                    .map(|_| ())
            }
            Operation::PairFinish | Operation::PairMismatch => {
                crate::pairing::finish(State(state), headers, self.request())
                    .await
                    .map(|_| ())
            }
            Operation::Messages | Operation::PairMessages => {
                messages::messages(State(state), headers, self.request())
                    .await
                    .map(|_| ())
            }
            Operation::Submit | Operation::Escalate => {
                messages::submit(State(state), headers, self.request())
                    .await
                    .map(|_| ())
            }
            Operation::Reply => {
                messages::reply(State(state), Path(self.id.clone()), headers, self.request())
                    .await
                    .map(|_| ())
            }
            Operation::Cancel => {
                messages::cancel(State(state), Path(self.id.clone()), headers, self.request())
                    .await
                    .map(|_| ())
            }
            Operation::Waiting => messages::waiting(
                State(state),
                OriginalUri("/v1/approvals?state=waiting".parse().unwrap()),
                headers,
            )
            .await
            .map(|_| ()),
            Operation::Ack => messages::ack(State(state), headers, self.request())
                .await
                .map(|_| ()),
            Operation::RevokeRecovery | Operation::RevokeStrong => auth::revoke(
                State(state),
                Path(self.id.clone()),
                peer,
                headers,
                self.request(),
            )
            .await
            .map(|_| ()),
            Operation::Cleanup => cleanup::cleanup(&state).map(|_| ()),
        }
    }
}

pub(crate) fn copy_state(source: &Arc<state::State>) -> Arc<state::State> {
    let mut db = Connection::open_in_memory().unwrap();
    {
        let source = source.data.lock().unwrap();
        rusqlite::backup::Backup::new(&source.db, &mut db)
            .unwrap()
            .run_to_completion(64, Duration::ZERO, None)
            .unwrap();
    }
    let mut copy = state::State::new(db, true).unwrap();
    Arc::get_mut(&mut copy).unwrap().recovery = source.recovery.clone();
    copy.advance(source.now() - now());
    {
        let source = source.data.lock().unwrap();
        let mut destination = copy.data.lock().unwrap();
        for (device, challenge) in &source.challenges {
            destination.challenges.insert(
                device.clone(),
                state::Challenge {
                    hash: challenge.hash.clone(),
                    exp: challenge.exp,
                },
            );
        }
    }
    copy
}

fn snapshot(state: &state::State) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    state
        .with(|data, _| {
            let mut tables = Vec::new();
            for table in [
                "accounts",
                "devices",
                "sessions",
                "pairings",
                "used_pair_tokens",
                "approvals",
                "messages",
            ] {
                let columns: Vec<String> = data
                    .db
                    .prepare(&format!("PRAGMA table_info({table})"))?
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<std::result::Result<_, _>>()?;
                // Delivery observations do not change durable acceptance or acknowledgement.
                let columns = columns
                    .into_iter()
                    .filter(|column| !["last_seen", "delivered_at"].contains(&column.as_str()))
                    .collect::<Vec<_>>();
                let mut query = data.db.prepare(&format!(
                    "SELECT {} FROM {table} ORDER BY rowid",
                    columns.join(",")
                ))?;
                let rows = query
                    .query_map([], |row| {
                        (0..columns.len())
                            .map(|index| {
                                let value: rusqlite::types::Value = row.get(index)?;
                                // SystemTime can tick between copies. Preserve whether
                                // revocation/resolution happened without comparing its second.
                                Ok(
                                    if ["revoked_at", "resolved_at"]
                                        .contains(&columns[index].as_str())
                                        && matches!(value, rusqlite::types::Value::Integer(_))
                                    {
                                        rusqlite::types::Value::Integer(1)
                                    } else {
                                        value
                                    },
                                )
                            })
                            .collect()
                    })?
                    .collect::<std::result::Result<Vec<Vec<rusqlite::types::Value>>, _>>()?;
                tables.push(rows);
            }
            Ok(tables)
        })
        .unwrap()
}

#[tokio::test]
async fn storage_faults_at_each_sql_prepare_and_execution_boundary_preserve_atomic_mutations() {
    let mut checked = 0;
    for operation in [
        Operation::Register,
        Operation::Challenge,
        Operation::Verify,
        Operation::PairStart,
        Operation::PairComplete,
        Operation::PairMigrate,
        Operation::PairFinish,
        Operation::PairMismatch,
        Operation::PairMessages,
        Operation::Messages,
        Operation::Submit,
        Operation::Escalate,
        Operation::Reply,
        Operation::Cancel,
        Operation::Waiting,
        Operation::Ack,
        Operation::RevokeRecovery,
        Operation::RevokeStrong,
        Operation::Cleanup,
    ] {
        let case = Case::new(operation);
        let baseline = case.copy_state();
        let prepares = Arc::new(AtomicUsize::new(0));
        {
            let data = baseline.data.lock().unwrap();
            let counter = prepares.clone();
            data.db.authorizer(Some(move |_: AuthContext<'_>| {
                counter.fetch_add(1, Ordering::Relaxed);
                Authorization::Allow
            }));
        }
        let result = case.run(baseline.clone()).await;
        if operation == Operation::PairMismatch {
            assert_eq!(result.unwrap_err().code, ErrorCode::Conflict);
        } else {
            result.unwrap();
        }
        {
            let data = baseline.data.lock().unwrap();
            data.db.progress_handler(0, None::<fn() -> bool>);
            data.db
                .authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> Authorization>);
        }
        let committed = snapshot(&baseline);
        for prepare in [true, false] {
            let count = prepares.load(Ordering::Relaxed);
            for fail_at in 1..=count {
                let relay = case.copy_state();
                let original = snapshot(&relay);
                {
                    let data = relay.data.lock().unwrap();
                    let mut calls = 0;
                    if prepare {
                        data.db.authorizer(Some(move |_: AuthContext<'_>| {
                            calls += 1;
                            if calls == fail_at {
                                Authorization::Deny
                            } else {
                                Authorization::Allow
                            }
                        }));
                    } else {
                        // Interrupt query execution as well as preparation. A
                        // progress callback may run after an autocommit write,
                        // so write/commit failures use the authorizer above.
                        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let progress = armed.clone();
                        let writing = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let executing_write = writing.clone();
                        data.db.authorizer(Some(move |context: AuthContext<'_>| {
                            calls += 1;
                            if matches!(
                                context.action,
                                rusqlite::hooks::AuthAction::Insert { .. }
                                    | rusqlite::hooks::AuthAction::Update { .. }
                                    | rusqlite::hooks::AuthAction::Delete { .. }
                                    | rusqlite::hooks::AuthAction::Transaction { .. }
                            ) {
                                writing.store(true, Ordering::Relaxed);
                            }
                            if calls == fail_at {
                                armed.store(true, Ordering::Relaxed);
                            }
                            Authorization::Allow
                        }));
                        data.db.progress_handler(
                            1,
                            Some(move || {
                                let armed = progress.swap(false, Ordering::Relaxed);
                                let writing = executing_write.swap(false, Ordering::Relaxed);
                                armed && !writing
                            }),
                        );
                    }
                }
                let result = case.run(relay.clone()).await;
                {
                    let data = relay.data.lock().unwrap();
                    data.db.progress_handler(0, None::<fn() -> bool>);
                    data.db
                        .authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> Authorization>);
                }
                if let Err(error) = result {
                    assert!(!format!("{error:?}").contains("fault-regression"));
                    let actual = snapshot(&relay);
                    assert!(actual == original || (operation == Operation::PairMismatch && actual == committed),
                        "partial durable mutation: {operation:?}, prepare={prepare}, fail_at={fail_at}");
                    if operation == Operation::RevokeStrong && actual == original {
                        let data = relay.data.lock().unwrap();
                        assert!(data.challenges.contains_key("dev_fault_approver"));
                    }
                }
                checked += 1;
            }
        }
    }
    assert!(
        checked > 1000,
        "exercise actual SQLite preparation and execution, not mocked results"
    );
    eprintln!("Checked {checked} SQLite fault boundaries.");
}

#[tokio::test]
async fn handlers_recheck_authentication_even_when_invoked_without_middleware() {
    for operation in [
        Operation::PairStart,
        Operation::PairFinish,
        Operation::Messages,
        Operation::Submit,
        Operation::Reply,
        Operation::Cancel,
        Operation::Waiting,
        Operation::Ack,
        Operation::RevokeRecovery,
    ] {
        let mut case = Case::new(operation);
        case.headers = HeaderMap::new();
        assert_eq!(
            case.run(case.copy_state()).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
    }
}

#[test]
fn query_binding_and_row_decoding_failures_are_sanitized() {
    let db = Connection::open_in_memory().unwrap();
    let read = |row: &rusqlite::Row<'_>| row.get::<_, String>(0);
    assert_eq!(
        state::query_rows(&db, "SELECT ?1", params![], read)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    db.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 64);
    assert_eq!(
        state::query_rows(
            &db,
            "SELECT ?1",
            params!["PRIVATE-BIND-ERROR".repeat(10)],
            read
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        state::query_rows(&db, "SELECT x'00'", params![], read)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}

#[test]
#[cfg(unix)]
fn permission_failures_stop_before_opening_or_exposing_storage() {
    let directory = tempfile::tempdir().unwrap();
    let absent = directory.path().join("missing");
    assert!(private_permissions(&absent, 0o700).is_err());
    for mode in [0o700, 0o600] {
        let error = prepare_storage(
            directory.path(),
            if mode == 0o700 {
                |_, _| {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "directory permission denied",
                    ))
                }
            } else {
                |path, mode| {
                    if mode == 0o600 {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "database permission denied",
                        ))
                    } else {
                        private_permissions(path, mode)
                    }
                }
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        if mode == 0o700 {
            assert!(!directory.path().join("relay.sqlite3").exists());
        }
    }
}

struct FailedPasswords {
    panic: bool,
}

impl auth::RecoveryPasswords for FailedPasswords {
    fn hash(&self, _: &str) -> Result<String> {
        assert!(!self.panic, "test password worker stopped");
        Err(ApiError::conflict())
    }

    fn verify(&self, _: &str, _: &str) -> Result<()> {
        assert!(!self.panic, "test password worker stopped");
        Err(ApiError::forbidden())
    }
}

#[tokio::test]
async fn password_worker_failures_and_panics_never_mutate_accounts() {
    for operation in [Operation::Register, Operation::RevokeRecovery] {
        for panic in [false, true] {
            let case = Case::new(operation);
            let mut relay = case.copy_state();
            Arc::get_mut(&mut relay).unwrap().recovery = Arc::new(FailedPasswords { panic });
            let original = snapshot(&relay);
            let error = case.run(relay.clone()).await.unwrap_err();
            assert_eq!(
                error.code,
                if !panic && operation == Operation::RevokeRecovery {
                    ErrorCode::Forbidden
                } else {
                    ErrorCode::Conflict
                }
            );
            assert_eq!(snapshot(&relay), original);
            assert!(relay.log.lock().unwrap().is_empty());
        }
    }
}

struct ChangingPasswords {
    relay: Mutex<std::sync::Weak<state::State>>,
    sql: &'static str,
}

impl auth::RecoveryPasswords for ChangingPasswords {
    fn hash(&self, _: &str) -> Result<String> {
        unreachable!("this verifier is never used to register devices")
    }

    fn verify(&self, _: &str, _: &str) -> Result<()> {
        self.relay
            .lock()
            .unwrap()
            .upgrade()
            .unwrap()
            .with(|data, _| {
                data.db.execute_batch(self.sql)?;
                Ok(())
            })
    }
}

#[tokio::test]
async fn recovery_rechecks_session_membership_target_and_readiness_after_password_work() {
    for (sql, code) in [
        ("UPDATE sessions SET exp=0 WHERE device_id='dev_fault_requester'", ErrorCode::Unauthorized),
        ("UPDATE pairings SET joiner_device='dev_fault_requester',state='accepted'", ErrorCode::Forbidden),
        ("UPDATE devices SET revoked_at=1 WHERE id='dev_fault_approver'", ErrorCode::NotFound),
        ("INSERT INTO accounts(id,created_at,recovery_hash) VALUES('acct_moved',0,'test-only'); UPDATE devices SET account_id='acct_moved' WHERE id='dev_fault_requester'", ErrorCode::Forbidden),
        ("DROP TABLE pairings", ErrorCode::Conflict),
    ] {
        let mut case = Case::new(Operation::RevokeRecovery);
        case.id = "dev_fault_approver".into();
        let mut relay = case.copy_state();
        let passwords = Arc::new(ChangingPasswords { relay: Mutex::new(std::sync::Weak::new()), sql });
        Arc::get_mut(&mut relay).unwrap().recovery = passwords.clone();
        *passwords.relay.lock().unwrap() = Arc::downgrade(&relay);
        assert_eq!(case.run(relay.clone()).await.unwrap_err().code, code);
        relay.with(|data, _| {
            let revoked: Option<i64> = data.db.query_row("SELECT revoked_at FROM devices WHERE id='dev_fault_approver'", [], |row| row.get(0))?;
            assert_eq!(revoked, if code == ErrorCode::NotFound { Some(1) } else { None });
            assert_eq!(data.db.query_row("SELECT state FROM approvals", [], |row| row.get::<_, String>(0))?, "waiting");
            Ok(())
        }).unwrap();
    }
}

#[tokio::test]
async fn corrupt_persisted_rows_fail_closed_without_partial_state_changes() {
    for (operation, table, columns) in [
        (
            Operation::Messages,
            "devices",
            &["account_id", "record"][..],
        ),
        (
            Operation::PairComplete,
            "pairings",
            &["pairing_id", "account_id", "initiator_pubs", "state", "exp"][..],
        ),
        (
            Operation::PairFinish,
            "pairings",
            &[
                "account_id",
                "initiator_device",
                "joiner_device",
                "state",
                "exp",
                "initiator_finished",
                "joiner_finished",
                "sas_hash",
            ][..],
        ),
        (
            Operation::Cancel,
            "approvals",
            &["requester", "state", "exp"][..],
        ),
        (Operation::Cancel, "messages", &["to_device"][..]),
        (Operation::Waiting, "messages", &["envelope"][..]),
        (Operation::RevokeRecovery, "approvals", &["id"][..]),
        (Operation::Cleanup, "approvals", &["account_id", "id"][..]),
        (Operation::Cleanup, "pairings", &["joiner_device"][..]),
    ] {
        let case = Case::new(operation);
        for column in columns {
            let relay = case.copy_state();
            relay.with(|data, _| {
                data.db.pragma_update(None, "foreign_keys", false)?;
                data.db.pragma_update(None, "ignore_check_constraints", true)?;
                let value = if *column == "record" || *column == "initiator_pubs" || *column == "envelope" { "42" } else { "x'00'" };
                data.db.execute(&format!("UPDATE {table} SET {column}={value} WHERE rowid=(SELECT MIN(rowid) FROM {table})"), [])?;
                Ok(())
            }).unwrap();
            let original = snapshot(&relay);
            let error = case.run(relay.clone()).await.unwrap_err();
            assert_eq!(
                error.code,
                ErrorCode::Conflict,
                "{operation:?}, {table}.{column}"
            );
            assert_eq!(
                snapshot(&relay),
                original,
                "{operation:?}, {table}.{column}"
            );
        }
    }
}

#[test]
fn canonical_key_failures_rsa_validation_and_schema_initialization_are_rejected() {
    let device = Device::new("canonical", true);
    let mut record = device.record.clone();
    record.ak_q.as_mut().unwrap().alg = SignatureAlgorithm::RS256;
    assert!(state::validate_device(&record).is_err());
    let rsa = SoftwareDeviceKey::generate_rsa2048().unwrap();
    record.ak_q.as_mut().unwrap().r#pub = rsa.public_jwk().unwrap();
    state::validate_device(&record).unwrap();
    let relay = crate::tests::fixture();
    for index in 0..3 {
        let mut record = device.record.clone();
        let key = match index {
            0 => &mut record.dk_pub,
            1 => &mut record.ak_q.as_mut().unwrap().r#pub,
            _ => &mut record.ak_s.as_mut().unwrap().r#pub,
        };
        key.extra.insert("unsafe_integer".into(), json!(u64::MAX));
        assert!(state::validate_device(&record).is_err());
        assert!(relay
            .state
            .with(|data, now| state::insert_device(
                &data.db,
                &relay.principal.account,
                &record,
                None,
                now
            ))
            .is_err());
    }
    let db = Connection::open_in_memory().unwrap();
    db.authorizer(Some(|context: AuthContext<'_>| {
        if matches!(
            context.action,
            rusqlite::hooks::AuthAction::CreateTable { .. }
        ) {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    }));
    assert!(state::State::new(db, true).is_err());
}

#[tokio::test]
async fn signed_outer_envelopes_reject_invalid_encodings_before_storage() {
    let fixture = crate::tests::fixture();
    let mut envelope = fixture.envelope.clone();
    envelope.enc = "not-base64!".into();
    let error = fixture
        .state
        .with(|data, now| messages::send_messages(data, &fixture.principal, &[envelope], now))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::BadEnvelope);
}

#[tokio::test]
async fn independent_auth_pairing_and_reply_rate_limits_return_the_contract_error() {
    for (operation, key, limit) in [
        (Operation::Challenge, "auth:127.0.0.1", 60),
        (Operation::Verify, "auth:127.0.0.1", 60),
        (Operation::RevokeRecovery, "revoke:127.0.0.1", 10),
        (Operation::PairStart, "pair:dev_fault_requester", 10),
        (Operation::PairComplete, "pair_complete:127.0.0.1", 60),
        (Operation::Reply, "messages:dev_fault_approver", 600),
    ] {
        let case = Case::new(operation);
        let relay = case.copy_state();
        relay
            .with(|data, now| data.rate(key.into(), now, limit, limit))
            .unwrap();
        let original = snapshot(&relay);
        assert_eq!(
            case.run(relay.clone()).await.unwrap_err().code,
            ErrorCode::RateLimited
        );
        assert_eq!(snapshot(&relay), original);
    }
}

#[tokio::test]
async fn pairing_rejects_invalid_joiners_consumed_expired_tokens_and_corrupt_public_records() {
    let mut invalid = Case::new(Operation::PairComplete);
    invalid.body["joiner"]["label"] = json!("x".repeat(257));
    assert_eq!(
        invalid.run(invalid.copy_state()).await.unwrap_err().code,
        ErrorCode::BadEnvelope
    );
    for (sql, code) in [
        ("UPDATE pairings SET state='accepted'", ErrorCode::Conflict),
        (
            "UPDATE pairings SET initiator_pubs=x'00'",
            ErrorCode::BadEnvelope,
        ),
        (
            "UPDATE used_pair_tokens SET exp=0; UPDATE pairings SET token_hash=NULL",
            ErrorCode::Expired,
        ),
        (
            "DELETE FROM pairings; DROP TABLE used_pair_tokens",
            ErrorCode::Conflict,
        ),
    ] {
        let case = Case::new(Operation::PairComplete);
        let relay = case.copy_state();
        relay
            .with(|data, _| {
                data.db.execute_batch(sql)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(case.run(relay).await.unwrap_err().code, code);
    }
    let case = Case::new(Operation::Waiting);
    let relay = case.copy_state();
    relay
        .with(|data, _| {
            data.db.execute("UPDATE messages SET envelope=x'00'", [])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        case.run(relay).await.unwrap_err().code,
        ErrorCode::BadEnvelope
    );
}

#[tokio::test]
async fn strong_proofs_fail_closed_with_missing_keys_challenges_or_invalid_encodings() {
    for (operation, device_id) in [
        (Operation::RevokeStrong, "dev_fault_approver"),
        (Operation::PairFinish, "dev_fault_requester"),
    ] {
        let case = Case::new(operation);
        let relay = case.copy_state();
        relay
            .with(|data, _| {
                let (_, mut device) = state::device(&data.db, device_id)?;
                device.caps = vec![Capability::ApproveStrong];
                device.ak_s = None;
                data.db.execute(
                    "UPDATE devices SET record=?1 WHERE id=?2",
                    params![serde_json::to_vec(&device).unwrap(), device_id],
                )?;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            case.run(relay).await.unwrap_err().code,
            ErrorCode::Forbidden
        );
    }
    let case = Case::new(Operation::RevokeStrong);
    let relay = case.copy_state();
    relay.data.lock().unwrap().challenges.clear();
    assert_eq!(
        case.run(relay).await.unwrap_err().code,
        ErrorCode::Unauthorized
    );
    let mut case = Case::new(Operation::RevokeStrong);
    case.headers
        .insert("x-kv-strong-signature", "not-base64!".parse().unwrap());
    assert_eq!(
        case.run(case.copy_state()).await.unwrap_err().code,
        ErrorCode::BadEnvelope
    );
}

#[test]
fn device_lookup_rejects_corrupt_account_record_types_and_invalid_json() {
    for (column, value, code) in [
        ("account_id", "x'00'", ErrorCode::Conflict),
        ("record", "42", ErrorCode::Conflict),
        ("record", "x'00'", ErrorCode::BadEnvelope),
    ] {
        let fixture = crate::tests::fixture();
        fixture
            .state
            .with(|data, _| {
                data.db.pragma_update(None, "foreign_keys", false)?;
                data.db
                    .execute(&format!("UPDATE devices SET {column}={value}"), [])?;
                assert_eq!(
                    state::device(&data.db, &fixture.principal.device.device_id)
                        .unwrap_err()
                        .code,
                    code
                );
                Ok(())
            })
            .unwrap();
    }
}

#[tokio::test]
async fn delivery_tracking_failures_preserve_successful_durable_acceptance() {
    for operation in [Operation::Messages, Operation::Submit, Operation::Reply] {
        let case = Case::new(operation);
        let relay = case.copy_state();
        let envelope = case
            .body
            .get("envelope")
            .unwrap_or_else(|| &case.body["envelopes"][0]);
        let recipient = envelope["to"].as_str().unwrap();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(128);
        relay.with(|data, _| {
            data.db.execute_batch("CREATE TRIGGER failed_tracking BEFORE UPDATE OF delivered_at ON messages BEGIN SELECT RAISE(ABORT,'PRIVATE-TRACKING-ERROR'); END;")?;
            data.presence.insert(recipient.into(), state::Presence { connection: "tracking-regression".into(), sender });
            Ok(())
        }).unwrap();
        case.run(relay.clone()).await.unwrap();
        let state::Outbound::Frame(frame) = receiver.try_recv().unwrap() else {
            panic!("expected envelope")
        };
        assert_eq!(frame["envelope"], *envelope);
        relay
            .with(|data, _| {
                let delivered: Option<i64> = data.db.query_row(
                    "SELECT delivered_at FROM messages WHERE id=?1 AND to_device=?2 AND type=?3",
                    params![
                        envelope["id"].as_str().unwrap(),
                        recipient,
                        envelope["type"].as_str().unwrap()
                    ],
                    |row| row.get(0),
                )?;
                assert_eq!(delivered, None);
                Ok(())
            })
            .unwrap();
        // A lost HTTP response can retry identical ciphertext without redelivery.
        case.run(relay.clone()).await.unwrap();
        assert!(receiver.try_recv().is_err());
        assert!(relay
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|line| !line.contains("PRIVATE")));
    }
}

#[tokio::test]
async fn strong_revocation_retries_failed_transactions_and_consumes_only_committed_proofs() {
    let case = Case::new(Operation::RevokeStrong);
    let relay = case.copy_state();
    let before = snapshot(&relay);
    relay.with(|data, _| { data.db.execute_batch("CREATE TRIGGER failed_revocation BEFORE UPDATE OF revoked_at ON devices BEGIN SELECT RAISE(ABORT,'PRIVATE-REVOKE-ERROR'); END;")?; Ok(()) }).unwrap();
    assert_eq!(
        case.run(relay.clone()).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(snapshot(&relay), before);
    relay
        .with(|data, _| {
            data.db.execute_batch("DROP TRIGGER failed_revocation")?;
            Ok(())
        })
        .unwrap();
    case.run(relay.clone()).await.unwrap();
    assert!(!relay
        .data
        .lock()
        .unwrap()
        .challenges
        .contains_key("dev_fault_approver"));
    assert_eq!(
        case.run(relay.clone()).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    relay
        .with(|data, _| {
            assert!(data
                .db
                .query_row(
                    "SELECT revoked_at FROM devices WHERE id='dev_fault_requester'",
                    [],
                    |row| row.get::<_, Option<i64>>(0)
                )?
                .is_some());
            assert_eq!(
                data.db
                    .query_row("SELECT state FROM approvals", [], |row| row
                        .get::<_, String>(0))?,
                "cancelled"
            );
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn production_lifecycle_covers_startup_failures_and_clean_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"test-only").unwrap();
    assert!(prepare_storage(&file, private_permissions).is_err());
    let unavailable = directory.path().join("unavailable");
    std::fs::create_dir_all(unavailable.join("relay.sqlite3")).unwrap();
    let corrupt = directory.path().join("corrupt");
    std::fs::create_dir(&corrupt).unwrap();
    std::fs::write(corrupt.join("relay.sqlite3"), b"test-only-corrupt-storage").unwrap();
    let valid = directory.path().join("valid");
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for (listen, path, succeeds) in [
        ("0.0.0.0:0".parse().unwrap(), &valid, false),
        ("127.0.0.1:0".parse().unwrap(), &file, false),
        ("127.0.0.1:0".parse().unwrap(), &unavailable, false),
        ("127.0.0.1:0".parse().unwrap(), &corrupt, false),
        (busy.local_addr().unwrap(), &valid, false),
        ("127.0.0.1:0".parse().unwrap(), &valid, true),
    ] {
        assert_eq!(
            run(listen, path.as_path(), std::future::ready(()))
                .await
                .is_ok(),
            succeeds
        );
    }
}
