use super::{RemoteError, Result};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub fn jcs<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    // CONTRACT: §6.2 / Appendix A: integers must survive all V1 JSON runtimes exactly.
    let raw = serde_json::to_vec(value).map_err(|_| RemoteError::InvalidJson)?;
    let json = parse_json(&raw)?;
    check_numbers(&json)?;
    let bytes = serde_jcs::to_vec(value).map_err(|_| RemoteError::InvalidJson)?;
    parse_json(&bytes)?;
    Ok(bytes)
}

fn check_numbers(value: &Value) -> Result<()> {
    match value {
        Value::Number(number) => {
            if number.as_u64().is_some_and(|n| n > MAX_SAFE_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() > MAX_SAFE_INTEGER)
            {
                return Err(RemoteError::InvalidJson);
            }
        }
        Value::Array(values) => {
            for value in values {
                check_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                check_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn canonicalize_json(bytes: &[u8]) -> Result<Vec<u8>> {
    jcs(&parse_json(bytes)?)
}

pub fn signed_payload<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| RemoteError::InvalidJson)?;
    let mut value = parse_json(&bytes)?;
    value
        .as_object_mut()
        .ok_or(RemoteError::InvalidJson)?
        .remove("sig");
    jcs(&value)
}

/// Hash native runtime executables without allocating their entire contents.
pub fn sha256_reader(mut reader: impl std::io::Read) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total += count as u64;
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// CONTRACT: §6.2: these are execution bindings, independent of ApprovalRequest display fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAction {
    pub kind: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAgent {
    pub runtime: String,
    pub repo_or_cwd: String,
    pub uid: u32,
    pub pid: u32,
    pub exe_sha256: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalRequest {
    pub v: u32,
    pub kind: super::ApprovalKind,
    pub requester: String,
    pub credential: Option<String>,
    pub action: CanonicalAction,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub query_keys: Vec<String>,
    pub body_sha256: Option<String>,
    pub headers_digest: Option<String>,
    pub agent: CanonicalAgent,
    pub purpose: String,
    pub nonce: String,
    pub exp: super::Timestamp,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl CanonicalRequest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.v != 1 {
            return Err(RemoteError::UnsupportedVersion);
        }
        let mut value = self.clone();
        if let Some(host) = value.host.as_mut() {
            if !host.is_ascii() || host.is_empty() {
                return Err(RemoteError::InvalidJson);
            }
            host.make_ascii_lowercase();
        }
        if let Some(path) = value.path.as_mut() {
            *path = normalize_path(path)?;
        }
        value
            .query_keys
            .sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        jcs(&value)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

// CONTRACT: §6.2: RFC 3986 §5.2.4, decode unreserved escapes, preserve reserved bytes and slashes.
pub fn normalize_path(path: &str) -> Result<String> {
    if !path.starts_with('/') || path.contains(['?', '#']) || path.chars().any(char::is_control) {
        return Err(RemoteError::InvalidJson);
    }
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let escape = bytes
                .get(index + 1..index + 3)
                .ok_or(RemoteError::InvalidJson)?;
            let text = std::str::from_utf8(escape).map_err(|_| RemoteError::InvalidJson)?;
            let byte = u8::from_str_radix(text, 16).map_err(|_| RemoteError::InvalidJson)?;
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                decoded.push(byte);
            } else {
                decoded.extend_from_slice(format!("%{byte:02X}").as_bytes());
            }
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let mut input = String::from_utf8(decoded).map_err(|_| RemoteError::InvalidJson)?;
    let mut output = String::new();
    while !input.is_empty() {
        if input.starts_with("../") {
            input.drain(..3);
        } else if input.starts_with("./") || input.starts_with("/./") {
            input.drain(..2);
        } else if input == "/." {
            input = "/".into();
        } else if input.starts_with("/../") || input == "/.." {
            input = if input == "/.." {
                "/".into()
            } else {
                input[3..].into()
            };
            output.truncate(output.rfind('/').unwrap_or(0));
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            let next = input[usize::from(input.starts_with('/'))..]
                .find('/')
                .map(|n| n + usize::from(input.starts_with('/')))
                .unwrap_or(input.len());
            output.push_str(&input[..next]);
            input.drain(..next);
        }
    }
    Ok(output)
}

pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        StrictValue::deserialize(&mut deserializer).map_err(|_| RemoteError::InvalidJson)?;
    deserializer.end().map_err(|_| RemoteError::InvalidJson)?;
    Ok(value.0)
}

pub fn from_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(parse_json(bytes)?).map_err(|_| RemoteError::InvalidJson)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unique JSON fields")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictValue(n.into()))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = a.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                    values.insert(key, a.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        d.deserialize_any(JsonVisitor)
    }
}
