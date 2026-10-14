//! Strict command parsing without adding a parser dependency.

use super::{Error, Result};
use kv_core::remote::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct Invocation {
    pub json: bool,
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) enum Command {
    Help(String),
    RelayInstall {
        listen: String,
        data: PathBuf,
        public_url: String,
        root: Option<PathBuf>,
    },
    RelayStatus {
        url: Option<String>,
    },
    RelaySetUrl {
        url: String,
    },
    RelayRecover {
        account_id: String,
        url: Option<String>,
        software: bool,
    },
    Pair {
        uri: Option<String>,
        rejoin: bool,
    },
    PairResume,
    DevicesList,
    DevicesRevoke {
        id: String,
    },
    DevicesRename {
        id: String,
        label: String,
    },
    Approvals {
        watch: bool,
        on_approve: Option<String>,
    },
    Decide {
        id: String,
        decision: Decision,
        scope: String,
        reason: Option<String>,
    },
    Grant {
        target: String,
        options: GrantOptions,
        unattended: bool,
        preauthorization: bool,
    },
    GrantList,
    GrantRevoke {
        jti: String,
    },
    Directive {
        target: String,
        op: DirectiveOp,
        args: Extra,
    },
    Status {
        summary: bool,
    },
    Audit {
        target: Option<String>,
        since: Option<String>,
        limit: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct GrantOptions {
    pub credential: Option<String>,
    pub all: bool,
    pub hosts: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
    pub paths: Option<Vec<String>>,
    pub agent: Option<String>,
    pub budget: Option<Budget>,
    pub until: Option<String>,
}

struct Options {
    positional: Vec<String>,
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

impl Options {
    fn parse(args: &[String], values: &[&str], flags: &[&str]) -> Result<Self> {
        let mut result = Self {
            positional: Vec::new(),
            values: BTreeMap::new(),
            flags: BTreeSet::new(),
        };
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            let (key, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(k, v)| (k, Some(v)));
            if values.contains(&key) {
                let value = match inline {
                    Some(value) => value.to_owned(),
                    None => {
                        index += 1;
                        args.get(index)
                            .filter(|s| !s.starts_with("--"))
                            .cloned()
                            .ok_or_else(|| {
                                Error::argument("选项缺少值", "An option requires a value")
                            })?
                    }
                };
                text(&value)?;
                if result.values.insert(key.into(), value).is_some() {
                    return Err(Error::argument(
                        "选项不能重复",
                        "An option cannot be repeated",
                    ));
                }
            } else if flags.contains(&key) && inline.is_none() {
                if !result.flags.insert(key.into()) {
                    return Err(Error::argument(
                        "选项不能重复",
                        "An option cannot be repeated",
                    ));
                }
            } else if arg.starts_with('-') {
                return Err(Error::argument(
                    "未知选项；请查看 --help",
                    "Unknown option; see --help",
                ));
            } else {
                text(arg)?;
                result.positional.push(arg.clone());
            }
            index += 1;
        }
        Ok(result)
    }

    fn count(&self, count: usize) -> Result<()> {
        if self.positional.len() == count {
            Ok(())
        } else {
            Err(Error::argument(
                "命令参数数量不正确；请查看 --help",
                "Incorrect number of command arguments; see --help",
            ))
        }
    }

    fn value(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
    fn required(&self, key: &str) -> Result<String> {
        self.value(key).ok_or_else(|| {
            Error::argument(
                "缺少必填选项；请查看 --help",
                "A required option is missing; see --help",
            )
        })
    }
    fn flag(&self, key: &str) -> bool {
        self.flags.contains(key)
    }
}

fn text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        Err(Error::argument(
            "参数不能为空、过长或含控制字符",
            "An argument is empty, too long or contains control characters",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn linux_pid_approval(argv: &[String]) -> bool {
    cfg!(target_os = "linux") && pid_approval(argv)
}

pub(super) fn pid_approval(argv: &[String]) -> bool {
    argv.len() == 2 && argv[0] == "approve" && argv[1].parse::<u32>().is_ok_and(|n| n != 0)
}

impl Invocation {
    pub fn parse(argv: &[String]) -> Result<Self> {
        let json = argv.iter().filter(|s| *s == "--json").count();
        if json > 1 {
            return Err(Error::argument(
                "--json 不能重复",
                "--json cannot be repeated",
            ));
        }
        let args: Vec<_> = argv.iter().filter(|s| *s != "--json").cloned().collect();
        let Some(cmd) = args.first() else {
            return Err(Error::argument("缺少命令", "A command is required"));
        };
        let rest = &args[1..];
        if rest.iter().any(|s| matches!(s.as_str(), "--help" | "-h")) {
            return Ok(Self {
                json: json == 1,
                command: Command::Help(cmd.clone()),
            });
        }
        let command = match cmd.as_str() {
            "audit" => {
                let options =
                    Options::parse(rest, &["--since", "--limit", "--device"], &["--remote"])?;
                options.count(0)?;
                if !options.flag("--remote") {
                    return Err(Error::argument(
                        "请使用 audit --remote",
                        "Use audit --remote",
                    ));
                }
                let limit = options
                    .value("--limit")
                    .map(|v| v.parse::<u32>())
                    .transpose()
                    .map_err(|_| Error::argument("分页大小应为 1–200", "Page size must be 1–200"))?
                    .unwrap_or(200);
                if !(1..=200).contains(&limit) {
                    return Err(Error::argument(
                        "分页大小应为 1–200",
                        "Page size must be 1–200",
                    ));
                }
                // Resolve relative time in execute(), against the injected clock.
                let since = options.value("--since");
                if let Some(value) = &since {
                    expiration_syntax(value)?;
                }
                Command::Audit {
                    target: options.value("--device"),
                    since,
                    limit,
                }
            }
            "relay" => parse_relay(rest)?,
            "pair" => {
                let options = Options::parse(rest, &[], &["--new", "--resume", "--rejoin"])?;
                if ["--new", "--resume", "--rejoin"]
                    .iter()
                    .filter(|flag| options.flag(flag))
                    .count()
                    > 1
                {
                    return Err(Error::argument(
                        "请选择新配对或继续配对",
                        "Choose a new pairing or resume",
                    ));
                }
                if options.flag("--resume") {
                    options.count(0)?;
                    Command::PairResume
                } else if options.flag("--new") {
                    options.count(0)?;
                    Command::Pair {
                        uri: None,
                        rejoin: false,
                    }
                } else {
                    options.count(1)?;
                    pair_uri(&options.positional[0])?;
                    Command::Pair {
                        uri: Some(options.positional[0].clone()),
                        rejoin: options.flag("--rejoin"),
                    }
                }
            }
            "devices" => {
                let options = Options::parse(rest, &[], &[])?;
                match options.positional.first().map(String::as_str) {
                    Some("list") => {
                        options.count(1)?;
                        Command::DevicesList
                    }
                    Some("revoke") => {
                        options.count(2)?;
                        identifier(&options.positional[1])?;
                        Command::DevicesRevoke {
                            id: options.positional[1].clone(),
                        }
                    }
                    Some("rename") => {
                        options.count(3)?;
                        identifier(&options.positional[1])?;
                        Command::DevicesRename {
                            id: options.positional[1].clone(),
                            label: options.positional[2].clone(),
                        }
                    }
                    _ => {
                        return Err(Error::argument(
                            "用法：devices list|revoke <id>|rename <id> <label>",
                            "Usage: devices list|revoke <id>|rename <id> <label>",
                        ))
                    }
                }
            }
            "approvals" => {
                let options = Options::parse(rest, &["--on-approve"], &["--watch"])?;
                options.count(0)?;
                Command::Approvals {
                    watch: options.flag("--watch") || options.value("--on-approve").is_some(),
                    on_approve: options.value("--on-approve"),
                }
            }
            "approve" | "deny" => {
                let values: &[&str] = if cmd == "approve" {
                    &["--scope"]
                } else {
                    &["--reason"]
                };
                let options = Options::parse(rest, values, &[])?;
                options.count(1)?;
                identifier(&options.positional[0])?;
                let selected = options.value("--scope").unwrap_or_else(|| "per_use".into());
                scope(&selected, 0)?;
                Command::Decide {
                    id: options.positional[0].clone(),
                    decision: if cmd == "approve" {
                        Decision::Allow
                    } else {
                        Decision::Deny
                    },
                    scope: selected,
                    reason: options.value("--reason"),
                }
            }
            "grant" => parse_grant(rest)?,
            "remote" => parse_remote(rest)?,
            "status" | "protection" => {
                let options = Options::parse(rest, &[], &["--summary"])?;
                options.count(0)?;
                Command::Status {
                    summary: options.flag("--summary"),
                }
            }
            _ => return Err(Error::argument("未知远程命令", "Unknown remote command")),
        };
        Ok(Self {
            json: json == 1,
            command,
        })
    }
}

fn parse_relay(args: &[String]) -> Result<Command> {
    let Some(action) = args.first() else {
        return Err(Error::argument(
            "用法：relay install|status|set-url|recover",
            "Usage: relay install|status|set-url|recover",
        ));
    };
    match action.as_str() {
        "recover" => {
            let options = Options::parse(&args[1..], &["--public-url"], &["--software"])?;
            options.count(1)?;
            let account_id = options.positional[0].clone();
            if account_id.is_empty()
                || account_id.len() > 256
                || account_id
                    .chars()
                    .any(|ch| ch.is_control() || ch.is_whitespace())
            {
                return Err(Error::argument("无效账户 ID", "Invalid account ID"));
            }
            let url = options.value("--public-url");
            if let Some(url) = &url {
                super::relay::RelayUrl::parse(url)?;
            }
            Ok(Command::RelayRecover {
                account_id,
                url,
                software: options.flag("--software"),
            })
        }
        "install" => {
            let options = Options::parse(
                &args[1..],
                &["--listen", "--data", "--public-url", "--root"],
                &[],
            )?;
            options.count(0)?;
            let listen = options
                .value("--listen")
                .unwrap_or_else(|| "127.0.0.1:8787".into());
            let address: std::net::SocketAddr = listen.parse().map_err(|_| {
                Error::argument("--listen 需要 IP:端口", "--listen requires IP:port")
            })?;
            if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || address.port() == 0
            {
                return Err(Error::argument(
                    "relay 只能监听 127.0.0.1 的非零端口",
                    "The relay must listen on 127.0.0.1 with a nonzero port",
                ));
            }
            let data = PathBuf::from(
                options
                    .value("--data")
                    .unwrap_or_else(|| "/var/lib/keyvalet-relay-server".into()),
            );
            // These are Linux deployment assets, also when staged on another platform.
            if !data
                .to_str()
                .is_some_and(|p| p.starts_with('/') && !p.split('/').any(|p| p == ".."))
            {
                return Err(Error::argument(
                    "--data 必须为 Linux 绝对路径且不能含 ..",
                    "--data must be an absolute Linux path without ..",
                ));
            }
            let root = options.value("--root").map(PathBuf::from);
            if let Some(root) = &root {
                absolute_path(root)?;
            }
            let public_url = options.required("--public-url")?;
            let url = super::relay::RelayUrl::parse(&public_url)?;
            if url.scheme != "https" || url.port != 443 || !url.path.is_empty() {
                return Err(Error::argument(
                    "--public-url 需要无路径的 HTTPS 地址",
                    "--public-url requires an HTTPS origin without a path",
                ));
            }
            Ok(Command::RelayInstall {
                listen,
                data,
                public_url,
                root,
            })
        }
        "status" => {
            let options = Options::parse(&args[1..], &["--public-url"], &[])?;
            options.count(0)?;
            let url = options.value("--public-url");
            if let Some(url) = &url {
                super::relay::RelayUrl::parse(url)?;
            }
            Ok(Command::RelayStatus { url })
        }
        "set-url" => {
            let options = Options::parse(&args[1..], &[], &[])?;
            options.count(1)?;
            super::relay::RelayUrl::parse(&options.positional[0])?;
            Ok(Command::RelaySetUrl {
                url: options.positional[0].clone(),
            })
        }
        _ => Err(Error::argument(
            "未知 relay 操作",
            "Unknown relay operation",
        )),
    }
}

fn parse_grant(args: &[String]) -> Result<Command> {
    match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 => Ok(Command::GrantList),
        Some("revoke") if args.len() == 2 => {
            identifier(&args[1])?;
            Ok(Command::GrantRevoke {
                jti: args[1].clone(),
            })
        }
        Some("revoke-all") if args.len() == 1 => Ok(Command::Directive {
            target: "*".into(),
            op: DirectiveOp::RevokeAllGrants,
            args: Extra::new(),
        }),
        _ => {
            let options = grant_options(args, true, false)?;
            options.count(0)?;
            let target = options.required("--to")?;
            let grant = build_grant_options(&options, true, false)?;
            Ok(Command::Grant {
                target,
                options: grant,
                unattended: false,
                preauthorization: true,
            })
        }
    }
}

fn grant_options(args: &[String], issue: bool, unattended: bool) -> Result<Options> {
    let mut values = vec![
        "--credential",
        "--hosts",
        "--methods",
        "--paths",
        "--agent",
        "--until",
    ];
    if issue {
        values.extend(["--to", "--budget"]);
    }
    let flags = if unattended {
        vec!["--include-sensitive"]
    } else if issue {
        vec![]
    } else {
        vec!["--standing", "--all"]
    };
    Options::parse(args, &values, &flags)
}

fn build_grant_options(options: &Options, issue: bool, unattended: bool) -> Result<GrantOptions> {
    let all = options.flag("--all") || unattended;
    let credential = options.value("--credential");
    if unattended && credential.is_some() {
        return Err(Error::argument(
            "unattended 的范围为执行端全部凭证",
            "unattended applies to all credentials on the executor",
        ));
    }
    if credential.is_some() == all {
        return Err(Error::argument(
            "必须选择 --credential 或 --all",
            "Choose exactly one of --credential and --all",
        ));
    }
    if let Some(credential) = &credential {
        if !credential
            .split_once('/')
            .is_some_and(|(kind, name)| !kind.is_empty() && !name.is_empty() && !name.contains('/'))
        {
            return Err(Error::argument(
                "--credential 需要 type/name",
                "--credential requires type/name",
            ));
        }
    }
    if options.flag("--standing") && options.value("--until").is_some() {
        return Err(Error::argument(
            "--standing 与 --until 不能同时使用",
            "--standing and --until are mutually exclusive",
        ));
    }
    if unattended && !options.flag("--include-sensitive") {
        return Err(Error::argument(
            "必须显式使用 --include-sensitive",
            "--include-sensitive is required",
        ));
    }
    let until_text = if issue || unattended {
        Some(options.required("--until")?)
    } else if options.flag("--standing") {
        None
    } else {
        Some(options.value("--until").unwrap_or_else(|| "1h".into()))
    };
    if let Some(until_text) = &until_text {
        expiration_syntax(until_text)?;
    }
    let hosts = list(options.value("--hosts"))?;
    if let Some(hosts) = &hosts {
        if hosts
            .iter()
            .any(|h| h.contains(['/', '@', '?', '#', ':', ' ']) || !h.is_ascii())
        {
            return Err(Error::argument(
                "--hosts 只能包含主机名",
                "--hosts must contain host names",
            ));
        }
    }
    let methods = list(options.value("--methods"))?;
    if let Some(methods) = &methods {
        if methods.iter().any(|m| {
            !matches!(
                m.as_str(),
                "GET"
                    | "HEAD"
                    | "POST"
                    | "PUT"
                    | "PATCH"
                    | "DELETE"
                    | "OPTIONS"
                    | "TRACE"
                    | "CONNECT"
            )
        }) {
            return Err(Error::argument("无效 HTTP 方法", "Invalid HTTP method"));
        }
    }
    let paths = list(options.value("--paths"))?;
    if paths
        .as_ref()
        .is_some_and(|p| p.iter().any(|p| !p.starts_with('/')))
    {
        return Err(Error::argument(
            "--paths 的每项必须以 / 开头",
            "Each --paths entry must start with /",
        ));
    }
    let budget = options
        .value("--budget")
        .map(|text| {
            let (calls, per) = text.split_once('/').ok_or_else(|| {
                Error::argument(
                    "--budget 格式为正整数/1h|24h|7d",
                    "--budget must be positive-count/1h|24h|7d",
                )
            })?;
            let calls = calls
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    Error::argument(
                        "预算调用次数必须为正整数",
                        "The budget call count must be positive",
                    )
                })?;
            let per = match per {
                "1h" => BudgetPeriod::OneHour,
                "24h" => BudgetPeriod::OneDay,
                "7d" => BudgetPeriod::SevenDays,
                _ => {
                    return Err(Error::argument(
                        "预算周期只能为 1h、24h 或 7d",
                        "The budget period must be 1h, 24h or 7d",
                    ))
                }
            };
            Ok(Budget {
                calls,
                per,
                bytes: Optional::Missing,
                extra: Extra::new(),
            })
        })
        .transpose()?;
    Ok(GrantOptions {
        credential,
        all,
        hosts,
        methods,
        paths,
        agent: options.value("--agent"),
        budget,
        until: until_text,
    })
}

fn list(value: Option<String>) -> Result<Option<Vec<String>>> {
    value
        .map(|value| {
            let list: Vec<_> = value.split(',').map(str::trim).map(str::to_owned).collect();
            if list.iter().any(String::is_empty) {
                return Err(Error::argument(
                    "列表不能含空项",
                    "A list cannot contain empty entries",
                ));
            }
            Ok(list)
        })
        .transpose()
}

fn parse_remote(args: &[String]) -> Result<Command> {
    let (Some(target), Some(action)) = (args.first(), args.get(1)) else {
        return Err(Error::argument(
            "用法：remote <device|label|*> <操作>",
            "Usage: remote <device|label|*> <action>",
        ));
    };
    text(target)?;
    let rest = &args[2..];
    if matches!(action.as_str(), "allow" | "unattended") {
        let unattended = action == "unattended";
        let options = grant_options(rest, false, unattended)?;
        options.count(0)?;
        return Ok(Command::Grant {
            target: target.clone(),
            options: build_grant_options(&options, false, unattended)?,
            unattended,
            preauthorization: false,
        });
    }
    let (op, args) = match action.as_str() {
        "mode" => {
            let options = Options::parse(rest, &[], &[])?;
            options.count(1)?;
            let mode = &options.positional[0];
            if !matches!(mode.as_str(), "per_use" | "per_credential" | "per_session")
                && !mode
                    .strip_prefix("remember:")
                    .is_some_and(|n| n.ends_with('h') && duration(n).is_ok())
            {
                return Err(Error::argument(
                    "无效授权模式",
                    "Invalid authorization mode",
                ));
            }
            (DirectiveOp::SetMode, json!({"mode":mode}))
        }
        "lock" | "status" | "pending" | "grants" | "revoke-all" => {
            Options::parse(rest, &[], &[])?.count(0)?;
            let op = match action.as_str() {
                "lock" => DirectiveOp::Lock,
                "status" => DirectiveOp::QueryStatus,
                "pending" => DirectiveOp::QueryPending,
                "grants" => DirectiveOp::QueryGrants,
                _ => DirectiveOp::RevokeAllGrants,
            };
            (op, json!({}))
        }
        "unlock-ttl" => {
            let options = Options::parse(rest, &[], &[])?;
            options.count(1)?;
            let value = &options.positional[0];
            let seconds = duration(&if value.bytes().all(|b| b.is_ascii_digit()) {
                format!("{value}h")
            } else {
                value.clone()
            })?;
            (DirectiveOp::SetUnlockTtl, json!({"seconds":seconds}))
        }
        "label" | "notify" => {
            let options = Options::parse(rest, &[], &[])?;
            options.count(1)?;
            let value = &options.positional[0];
            if action == "notify"
                && !matches!(value.as_str(), "prefer-local" | "always-phone" | "both")
            {
                return Err(Error::argument(
                    "notify 需要 prefer-local、always-phone 或 both",
                    "notify requires prefer-local, always-phone or both",
                ));
            }
            if action == "label" {
                (DirectiveOp::SetDeviceLabel, json!({"label":value}))
            } else {
                (DirectiveOp::Notify, json!({"policy":value}))
            }
        }
        "class" => {
            let options = Options::parse(rest, &["--credential", "--host", "--exp"], &[])?;
            options.count(1)?;
            let exp = duration(&options.required("--exp")?)?;
            if !(5..=604800).contains(&exp) {
                return Err(Error::argument(
                    "class 的有效期必须在 5 秒与 7 天之间",
                    "Class expiration must be between 5 seconds and 7 days",
                ));
            }
            let mut matcher = Extra::new();
            if let Some(credential) = options.value("--credential") {
                matcher.insert("credential".into(), json!(credential));
            }
            if let Some(host) = options.value("--host") {
                matcher.insert("host".into(), json!(host));
            }
            (
                DirectiveOp::SetClass,
                json!({"name":options.positional[0],"match":matcher,"exp_s":exp}),
            )
        }
        "audit" => {
            let options = Options::parse(rest, &["--since", "--limit"], &[])?;
            options.count(0)?;
            let since = options.value("--since").unwrap_or_else(|| "24h".into());
            expiration_syntax(&since)?;
            let limit = options
                .value("--limit")
                .unwrap_or_else(|| "100".into())
                .parse::<u32>()
                .ok()
                .filter(|n| (1..=200).contains(n))
                .ok_or_else(|| {
                    Error::argument(
                        "--limit 必须为 1 到 200",
                        "--limit must be between 1 and 200",
                    )
                })?;
            (
                DirectiveOp::QueryAudit,
                json!({"since_text":since,"limit":limit}),
            )
        }
        "grant" => {
            if rest.len() == 1 && rest[0] == "revoke-all" {
                (DirectiveOp::RevokeAllGrants, json!({}))
            } else {
                if rest.len() != 2 || rest[0] != "revoke" {
                    return Err(Error::argument(
                        "用法：remote <device> grant revoke <jti> | revoke-all",
                        "Usage: remote <device> grant revoke <jti> | revoke-all",
                    ));
                }
                identifier(&rest[1])?;
                (DirectiveOp::RevokeGrant, json!({"jti":rest[1]}))
            }
        }
        _ => {
            return Err(Error::argument(
                "未知 remote 操作；请查看 remote --help",
                "Unknown remote action; see remote --help",
            ))
        }
    };
    Ok(Command::Directive {
        target: target.clone(),
        op,
        args: args.as_object().cloned().unwrap_or_default(),
    })
}

fn identifier(value: &str) -> Result<()> {
    text(value)?;
    if value == "*" || value.chars().any(char::is_whitespace) {
        return Err(Error::argument(
            "需要单个标识符",
            "A single identifier is required",
        ));
    }
    Ok(())
}

fn absolute_path(path: &std::path::Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        Err(Error::argument(
            "路径必须为绝对路径且不能含 ..",
            "Paths must be absolute and cannot contain ..",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn pair_uri(uri: &str) -> Result<()> {
    let (authority, token) = uri
        .strip_prefix("kv-pair://")
        .and_then(|s| s.split_once('/'))
        .ok_or_else(|| {
            Error::argument(
                "需要 kv-pair:// 配对地址",
                "A kv-pair:// pairing URI is required",
            )
        })?;
    super::relay::RelayUrl::parse(&format!("https://{authority}"))?;
    if token.len() != 26
        || !token
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
        || !matches!(
            token.as_bytes()[25],
            b'A' | b'E' | b'I' | b'M' | b'Q' | b'U' | b'Y' | b'4'
        )
    {
        return Err(Error::argument(
            "配对 token 格式不正确；请重新运行 pair --new",
            "Invalid pairing token; run pair --new again",
        ));
    }
    Ok(())
}

pub(super) fn duration(text: &str) -> Result<u64> {
    let error = || {
        Error::argument(
            "时长需要正整数和 s、m、h 或 d",
            "A duration requires a positive integer and s, m, h or d",
        )
    };
    let unit = text.as_bytes().last().copied().ok_or_else(error)?;
    let multiplier = match unit {
        b's' => 1,
        b'm' => 60,
        b'h' => 3600,
        b'd' => 86400,
        _ => return Err(error()),
    };
    let number = &text[..text.len() - 1];
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(error());
    }
    number
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(error)
}

fn expiration_syntax(text: &str) -> Result<()> {
    if text.contains(['T', 't']) {
        timestamp(text).map(|_| ())
    } else {
        duration(text).map(|_| ())
    }
}

pub(super) fn until(text: &str, now: i64) -> Result<i64> {
    let date = if text.contains(['T', 't']) {
        timestamp(text)?
    } else {
        now.checked_add(duration(text)? as i64)
            .ok_or_else(|| Error::argument("有效期溢出", "Expiration overflows"))?
    };
    if date <= now {
        return Err(Error::argument(
            "到期时间必须在未来",
            "Expiration must be in the future",
        ));
    }
    Ok(date)
}

pub(super) fn since(text: &str, now: i64) -> Result<i64> {
    let date = if text.contains(['T', 't']) {
        timestamp(text)?
    } else {
        now.checked_sub(duration(text)? as i64)
            .ok_or_else(|| Error::argument("时间范围溢出", "Time range overflows"))?
    };
    if date > now {
        return Err(Error::argument(
            "--since 不能在未来",
            "--since cannot be in the future",
        ));
    }
    Ok(date)
}

/// RFC 3339, also accepting minute precision for the documented grant example.
/// Fractional seconds round down because the wire expiration is an integer timestamp.
fn timestamp(text: &str) -> Result<i64> {
    let error = || {
        Error::argument(
            "时间需要 RFC 3339 格式及明确时区",
            "A timestamp requires RFC 3339 with an explicit time zone",
        )
    };
    let bytes = text.as_bytes();
    if !text.is_ascii()
        || bytes.len() < 17
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
    {
        return Err(error());
    }
    let number = |start: usize, end: usize| -> Result<i64> {
        text.get(start..end)
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .ok_or_else(error)
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let (second, mut zone_start) = if bytes.get(16) == Some(&b':') {
        (number(17, 19)?, 19)
    } else {
        (0, 16)
    };
    if bytes.get(zone_start) == Some(&b'.') {
        let digits = bytes[zone_start + 1..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if zone_start == 16 || digits == 0 {
            return Err(error());
        }
        zone_start += digits + 1;
    }
    let zone = text.get(zone_start..).ok_or_else(error)?;
    let offset = if matches!(zone, "Z" | "z") {
        0
    } else {
        if zone.len() != 6
            || !matches!(zone.as_bytes()[0], b'+' | b'-')
            || zone.as_bytes()[3] != b':'
        {
            return Err(error());
        }
        let hours = number(zone_start + 1, zone_start + 3)?;
        let minutes = number(zone_start + 4, zone_start + 6)?;
        if hours > 23 || minutes > 59 {
            return Err(error());
        }
        (hours * 3600 + minutes * 60) * if zone.starts_with('-') { -1 } else { 1 }
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return Err(error()),
    };
    if year < 1 || day < 1 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err(error());
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second - offset)
}

pub(super) fn scope(value: &str, now: i64) -> Result<DecisionScope> {
    let (mode, level, until) = match value {
        "per_use" => (ScopeMode::PerUse, DecisionScopeLevel::Credential, 0),
        "per_credential" => (ScopeMode::PerCredential, DecisionScopeLevel::Credential, 0),
        "per_session" => (ScopeMode::PerSession, DecisionScopeLevel::Device, 0),
        "standing:credential" => (ScopeMode::Standing, DecisionScopeLevel::Credential, 0),
        "standing:device" => (ScopeMode::Standing, DecisionScopeLevel::Device, 0),
        "remember:1h" | "remember:8h" | "remember:24h" => (
            ScopeMode::Remember,
            DecisionScopeLevel::Credential,
            until(value.strip_prefix("remember:").unwrap_or(""), now)?,
        ),
        _ => return Err(Error::argument("审批范围不正确", "Invalid approval scope")),
    };
    Ok(DecisionScope {
        mode,
        level,
        until,
        extra: Extra::new(),
    })
}

pub(super) fn help(topic: &str) -> String {
    let commands = match topic {
        "relay" => "relay install [--listen 127.0.0.1:8787] [--data /var/lib/keyvalet-relay-server] --public-url https://relay.example.com [--root /staging]\nrelay status [--public-url URL]\nrelay set-url <URL>\nrelay recover <account-id> [--public-url URL] [--software] (recovery code from hidden input or stdin)",
        "pair" => "pair --new\npair <kv-pair://host/base32-token>\npair --resume",
        "devices" => "devices list\ndevices revoke <id>\ndevices rename <id> <label>",
        "approvals" => "approvals [--watch] [--on-approve <cmd>]\napprove <id> [--scope per_use|per_credential|per_session|remember:1h|remember:8h|remember:24h|standing:credential|standing:device]\ndeny <id> [--reason <text>]",
        "approve" => "approve <id> [--scope ...]\napprove <pid> (Linux polkit)",
        "deny" => "deny <id> [--reason <text>]",
        "grant" => "grant --to <device|label|*> --credential type/name [--hosts host,...] [--methods GET,POST] [--paths /path,...] [--budget calls/1h|24h|7d] --until <duration|RFC3339> [--agent identity]\ngrant list\ngrant revoke <jti>\ngrant revoke-all",
        "status" | "protection" => "status [--summary]",
        "audit" => "audit --remote [--device <device|label>] [--since duration|RFC3339] [--limit 1..200] [--json]",
        _ => "relay install|status|set-url|recover\npair --new | pair <kv-pair://...>\ndevices list|revoke <id>|rename <id> <label>\napprovals [--watch] [--on-approve <cmd>] | approve <id> [--scope ...] | deny <id> [--reason ...]\ngrant ...|list|revoke <jti>|revoke-all\nremote <device|label|*> mode <per_use|per_credential|per_session|remember:Nh>\nremote <device|label|*> allow <--credential type/name|--all> [--hosts ...] [--methods ...] [--paths ...] [--agent ...] [--until duration|RFC3339|--standing]\nremote <device|label|*> unattended --include-sensitive --until <duration|RFC3339>\nremote <device|label|*> lock\nremote <device|label|*> unlock-ttl <hours|duration>\nremote <device|label|*> class <name> [--credential pattern] [--host pattern] --exp <duration>\nremote <device|label|*> label <label>\nremote <device|label|*> notify <prefer-local|always-phone|both>\nremote <device|label|*> status|pending|grants\nremote <device|label|*> audit [--since duration|RFC3339] [--limit 1..200]\nremote <device|label|*> grant revoke <jti> | revoke-all\nstatus [--summary]",
    };
    format!("{}\n\n{}\n\n{}", kv_i18n::t("用法：keyvalet <命令> [--json]", "Usage: keyvalet <command> [--json]"), commands, kv_i18n::t("设备可使用 id、标签或 *。密钥、签名及认证由 helper 处理。无人值守必须在终端输入执行端标签。", "Devices accept an id, label or *. The helper owns keys, signatures and authentication. Unattended mode requires typing the executor label in a terminal."))
}
