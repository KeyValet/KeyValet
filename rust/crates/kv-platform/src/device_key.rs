//! Device identity and approval keys are distinct from vault master keys.
pub use kv_ipc::remote::{DeviceKeyError, DeviceKeyProvider, SignatureAlgorithm};
use serde_json::Value;
use zeroize::Zeroizing;

#[cfg(any(target_os = "macos", windows))]
pub mod agent;
#[cfg(unix)]
pub mod software;
#[cfg(target_os = "linux")]
pub mod tpm;
#[cfg(windows)]
pub mod windows;

pub type Result<T> = std::result::Result<T, DeviceKeyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    Identity,
    Quick,
    Strong,
}
impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Quick => "quick",
            Self::Strong => "strong",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "identity" => Ok(Self::Identity),
            "quick" => Ok(Self::Quick),
            "strong" => Ok(Self::Strong),
            _ => Err(DeviceKeyError::InvalidKey),
        }
    }
    pub fn presence_kind(self) -> &'static str {
        match self {
            Self::Identity => "none",
            Self::Quick => "unlocked",
            Self::Strong => {
                #[cfg(windows)]
                {
                    "windows_hello"
                }
                #[cfg(target_os = "macos")]
                {
                    "touchid"
                }
                #[cfg(target_os = "linux")]
                {
                    "polkit"
                }
            }
        }
    }
}

pub fn key_name_valid(name: &str, role: KeyRole) -> bool {
    let prefix = format!("keyvalet.remote.{}.", role.as_str());
    name.strip_prefix(&prefix)
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn encode_b64(bytes: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(CHARS[(a >> 2) as usize] as char);
        out.push(CHARS[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[(((b & 15) << 2) | (c >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(CHARS[(c & 63) as usize] as char);
        }
    }
    out
}

pub fn decode_b64(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 3 / 4));
    let mut bits = 0u32;
    let mut count = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(DeviceKeyError::InvalidKey),
        };
        bits = (bits << 6) | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    if count == 6 || (count > 0 && bits & ((1 << count) - 1) != 0) {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(out)
}

pub fn p256_jwk(point: &[u8]) -> Result<Value> {
    if point.len() != 65 || point[0] != 4 {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(
        serde_json::json!({"kty":"EC", "crv":"P-256", "x":encode_b64(&point[1..33]), "y":encode_b64(&point[33..65])}),
    )
}

pub fn jwk_point(jwk: &Value) -> Result<Vec<u8>> {
    if jwk["kty"] != "EC"
        || jwk["crv"] != "P-256"
        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|k| jwk.get(k).is_some())
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    let x = decode_b64(jwk["x"].as_str().ok_or(DeviceKeyError::InvalidKey)?)?;
    let y = decode_b64(jwk["y"].as_str().ok_or(DeviceKeyError::InvalidKey)?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(DeviceKeyError::InvalidKey);
    }
    let mut point = vec![4];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn base64_is_canonical_unpadded_and_strict() {
        for n in 0..65 {
            let bytes: Vec<_> = (0..n).collect();
            let encoded = encode_b64(&bytes);
            assert!(decode_b64(&encoded).unwrap().as_slice() == bytes);
        }
        for invalid in ["A", "AB", "ABC", "Zg=", "Zg\n", "Z+", "Z/"] {
            assert!(decode_b64(invalid).is_err());
        }
        assert_eq!(encode_b64(b"f"), "Zg");
        assert_eq!(encode_b64(&[0xfb, 0xff, 0xff]), "-___");
        assert_eq!(decode_b64("-___").unwrap().as_slice(), [0xfb, 0xff, 0xff]);
    }

    #[test]
    fn roles_and_key_names_cannot_cross_namespaces() {
        for role in [KeyRole::Identity, KeyRole::Quick, KeyRole::Strong] {
            assert_eq!(KeyRole::parse(role.as_str()), Ok(role));
            let name = format!("keyvalet.remote.{}.{}", role.as_str(), "01ab".repeat(8));
            assert!(key_name_valid(&name, role));
            for other in [KeyRole::Identity, KeyRole::Quick, KeyRole::Strong] {
                assert_eq!(key_name_valid(&name, other), role == other);
            }
            for invalid in [
                format!("keyvalet.remote.{}.", role.as_str()),
                format!("keyvalet.remote.{}.{}", role.as_str(), "0".repeat(31)),
                format!("keyvalet.remote.{}.{}", role.as_str(), "0".repeat(33)),
                format!("keyvalet.remote.{}.{}", role.as_str(), "g".repeat(32)),
                format!("{name}/../key"),
            ] {
                assert!(!key_name_valid(&invalid, role));
            }
        }
        assert_eq!(KeyRole::parse("unknown"), Err(DeviceKeyError::InvalidKey));
        assert_eq!(KeyRole::Identity.presence_kind(), "none");
        assert_eq!(KeyRole::Quick.presence_kind(), "unlocked");
        #[cfg(target_os = "macos")]
        assert_eq!(KeyRole::Strong.presence_kind(), "touchid");
        #[cfg(windows)]
        assert_eq!(KeyRole::Strong.presence_kind(), "windows_hello");
        #[cfg(target_os = "linux")]
        assert_eq!(KeyRole::Strong.presence_kind(), "polkit");
    }

    #[test]
    fn p256_jwk_rejects_private_material_and_malformed_coordinates() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kv-core/testdata/remote/test_keys.json");
        let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let public = &vector["sender"]["public_jwk"];
        let point = jwk_point(public).unwrap();
        assert_eq!(p256_jwk(&point).unwrap(), *public);
        for invalid in [vec![], vec![4; 64], vec![4; 66], vec![3; 65]] {
            assert_eq!(p256_jwk(&invalid), Err(DeviceKeyError::InvalidKey));
        }
        for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let mut invalid = public.clone();
            invalid[field] = Value::Null;
            assert_eq!(jwk_point(&invalid), Err(DeviceKeyError::InvalidKey));
        }
        for (field, value) in [
            ("kty", json!("RSA")),
            ("crv", json!("P-384")),
            ("x", Value::Null),
            ("y", Value::Null),
            ("x", json!("!")),
            ("y", json!("!")),
            ("x", json!(encode_b64(&[1; 31]))),
            ("y", json!(encode_b64(&[1; 33]))),
        ] {
            let mut invalid = public.clone();
            invalid[field] = value;
            assert_eq!(jwk_point(&invalid), Err(DeviceKeyError::InvalidKey));
        }
    }
}
