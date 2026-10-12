//! The helper owns the CA; a user proxy sends only a CSR and retains its leaf key in memory.

use rcgen::{CertificateParams, CertificateSigningRequestParams, KeyPair, SanType};
use std::time::{Duration, SystemTime};
use tokio_rustls::rustls;
use zeroize::Zeroizing;

struct SigningKey(Zeroizing<KeyPair>);
impl rcgen::PublicKeyData for SigningKey {
    fn der_bytes(&self) -> &[u8] {
        rcgen::PublicKeyData::der_bytes(&*self.0)
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        rcgen::PublicKeyData::algorithm(&*self.0)
    }
}
impl rcgen::SigningKey for SigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        rcgen::SigningKey::sign(&*self.0, message)
    }
}

pub struct CertificateAuthority {
    issuer: rcgen::Issuer<'static, SigningKey>,
    certificate: String,
}

impl CertificateAuthority {
    pub fn open(vault: &kv_vault::Vault) -> Result<Self, String> {
        let stored = vault
            .authenticated_metadata("proxy_ca")
            .map_err(|_| "Proxy CA storage is unavailable")?;
        if let Some(mut stored) = stored {
            let loaded = (|| {
                let certificate = stored["certificate"]
                    .as_str()
                    .ok_or("Invalid proxy CA metadata")?
                    .to_owned();
                let key = SigningKey(Zeroizing::new(
                    KeyPair::from_pem(
                        stored["private_key"]
                            .as_str()
                            .ok_or("Invalid proxy CA metadata")?,
                    )
                    .map_err(|_| "Invalid proxy CA key")?,
                ));
                let issuer = rcgen::Issuer::from_ca_cert_pem(&certificate, key)
                    .map_err(|_| "Invalid proxy CA certificate")?;
                Ok(Self {
                    issuer,
                    certificate,
                })
            })();
            kv_vault::scrub_json(&mut stored);
            return loaded;
        }
        let key = SigningKey(Zeroizing::new(
            KeyPair::generate().map_err(|_| "Cannot generate proxy CA key")?,
        ));
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "KeyValet session proxy CA");
        params.not_before = (SystemTime::now() - Duration::from_secs(300)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(10 * 365 * 86400)).into();
        let certificate = params
            .self_signed(&key)
            .map_err(|_| "Cannot sign proxy CA")?
            .pem();
        let private = Zeroizing::new(key.0.serialize_pem());
        let mut metadata =
            serde_json::json!({"certificate":certificate,"private_key":private.as_str()});
        let saved = vault.replace_authenticated_metadata("proxy_ca", None, metadata.clone());
        kv_vault::scrub_json(&mut metadata);
        saved.map_err(|_| "Cannot store proxy CA")?;
        Ok(Self {
            issuer: rcgen::Issuer::new(params, key),
            certificate,
        })
    }

    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    pub fn sign_leaf(&self, host: &str, csr: &str) -> Result<Vec<u8>, String> {
        if !valid_host(host) || csr.len() > 16 * 1024 {
            return Err("Invalid proxy CSR".into());
        }
        let mut request = CertificateSigningRequestParams::from_pem(csr)
            .map_err(|_| "Invalid proxy CSR signature")?;
        if request.public_key.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
            return Err("Proxy leaf keys must use P-256".into());
        }
        let names = &request.params.subject_alt_names;
        if names.len() != 1 || !matches!(&names[0], SanType::DnsName(name) if name.as_str() == host)
        {
            return Err("Proxy CSR does not match the bound host".into());
        }
        request.params =
            CertificateParams::new(vec![host.into()]).map_err(|_| "Invalid proxy host")?;
        request.params.is_ca = rcgen::IsCa::NoCa;
        request.params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        request.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        request.params.not_before = (SystemTime::now() - Duration::from_secs(300)).into();
        request.params.not_after = (SystemTime::now() + Duration::from_secs(86400)).into();
        Ok(request
            .signed_by(&self.issuer)
            .map_err(|_| "Cannot sign proxy leaf")?
            .der()
            .to_vec())
    }
}

pub struct LeafRequest {
    key: Zeroizing<KeyPair>,
    pub csr: String,
}

impl LeafRequest {
    pub fn new(host: &str) -> Result<Self, String> {
        if !valid_host(host) {
            return Err("Invalid proxy host".into());
        }
        let key =
            Zeroizing::new(KeyPair::generate().map_err(|_| "Cannot generate proxy leaf key")?);
        let params = CertificateParams::new(vec![host.into()]).map_err(|_| "Invalid proxy host")?;
        let csr = params
            .serialize_request(&*key)
            .map_err(|_| "Cannot create proxy CSR")?
            .pem()
            .map_err(|_| "Cannot encode proxy CSR")?;
        Ok(Self { key, csr })
    }
    pub fn accept(self, certificate: Vec<u8>) -> Result<rustls::ServerConfig, String> {
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(self.key.serialize_der()).into();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "Invalid TLS protocol configuration")?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.into()], key)
            .map_err(|_| "Proxy leaf certificate does not match its key")?;
        Ok(config)
    }
}

pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
