"""Regenerate public fixtures with Python cryptography, independent of the Rust implementation.

All private keys here are test-only. The RSA fixture is reused across runs.
Run: python3 rust/crates/kv-core/testdata/remote/generate.py
"""

import base64
import copy
import hashlib
import hmac
import json
import re
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve().parent
CORE = HERE.parent.parent
SCHEMAS = CORE / "schemas" / "remote"
SCHEMAS.mkdir(parents=True, exist_ok=True)
NOW = 1760200012
ID = "01J9W000000000000000000001"
NONCE = base64.urlsafe_b64encode(bytes(range(16))).decode().rstrip("=")


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(value):
    # These fixtures use integers only; floating-point JCS cases below are literal RFC outputs.
    def ordered(v):
        if isinstance(v, dict):
            return {k: ordered(v[k]) for k in sorted(v, key=lambda k: k.encode("utf-16be"))}
        if isinstance(v, list):
            return [ordered(x) for x in v]
        return v
    return json.dumps(ordered(value), ensure_ascii=False, separators=(",", ":")).encode()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def pub(key):
    numbers = key.public_key().public_numbers()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"kty": "EC", "crv": "P-256", "x": b64(numbers.x.to_bytes(32, "big")), "y": b64(numbers.y.to_bytes(32, "big"))}
    return {"kty": "RSA", "n": b64(numbers.n.to_bytes(256, "big")), "e": b64(numbers.e.to_bytes(3, "big"))}


KEYS = {name: ec.derive_private_key(value, ec.SECP256R1()) for name, value in
        [("sender", 1), ("recipient", 2), ("quick", 3), ("strong", 4), ("wrong", 5), ("ephemeral", 6)]}
key_path = HERE / "test_keys.json"
if key_path.exists():
    RSA_KEY = serialization.load_der_private_key(unb64(json.loads(key_path.read_text())["rsa_pkcs8_der"]), None)
else:
    RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KEYS["rsa"] = RSA_KEY
KEY_DATA = {name: {"private_scalar": b64(key.private_numbers().private_value.to_bytes(32, "big")), "public_jwk": pub(key)}
            for name, key in KEYS.items() if name != "rsa"}
KEY_DATA["rsa_pkcs8_der"] = b64(RSA_KEY.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
KEY_DATA["rsa_public_jwk"] = pub(RSA_KEY)
KEY_DATA["notice"] = "Fixed test keys only. Never install or use these keys in production."
KEY_DATA["expect"] = {"p256_roundtrips": {name: True for name in KEYS if name != "rsa"}, "rsa_roundtrip": True,
                      "rsa_ecdh_error": "unsupported_algorithm", "p256_wrong_algorithm": "unsupported_algorithm", "presence": "none", "key_kind": "software"}
write("test_keys.json", KEY_DATA)


def sign_bytes(key, payload):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        der = key.sign(payload, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def signed(value, key):
    result = copy.deepcopy(value)
    result.pop("sig", None)
    result["sig"] = b64(sign_bytes(key, canonical(result)))
    return result


def device(name, approver=False, rsa_strong=False):
    return {"device_id": "dev_mac" if approver else "dev_srv", "label": "MacBook" if approver else "srv",
            "os": "macos" if approver else "linux", "key_kind": "software", "dk_pub": pub(KEYS[name]),
            "ak_q": {"pub": pub(KEYS["quick"]), "alg": "ES256"} if approver else None,
            "ak_s": {"pub": pub(KEYS["rsa" if rsa_strong else "strong"]), "alg": "RS256" if rsa_strong else "ES256"} if approver else None,
            "caps": ["approve_quick", "approve_strong"] if approver else ["execute"], "attestation": None}


SERVER = device("sender")
APPROVER = device("recipient", True)
canonical_input = {"v": 1, "kind": "use", "requester": "dev_srv", "credential": "github/default", "action": {"kind": "http"},
                   "method": "POST", "host": "API.GITHUB.COM", "path": "/repos/guang/./demo/../demo/issues", "query_keys": ["z", "a", "a"],
                   "body_sha256": hashlib.sha256(b'{"title":"Fix"}').hexdigest(), "headers_digest": hashlib.sha256(b"{}").hexdigest(),
                   "agent": {"runtime": "claude-code", "repo_or_cwd": "/home/u/proj", "uid": 501, "pid": 4242,
                             "exe_sha256": hashlib.sha256(b"kv-test-agent").hexdigest()},
                   "purpose": "Create an issue", "nonce": NONCE, "exp": 1760200600}
normalized = copy.deepcopy(canonical_input)
normalized.update(host="api.github.com", path="/repos/guang/demo/issues", query_keys=["a", "a", "z"])
DIGEST = hashlib.sha256(canonical(normalized)).hexdigest()
write("approval_request_digest.json", {"input": canonical_input, "expect": {"canonical": canonical(normalized).decode(), "digest": DIGEST}})
OPTIONS = ["per_use", "per_credential", "per_session", "remember:1h", "remember:8h", "remember:24h", "standing:credential", "standing:device"]
REQUEST = {"approval_id": ID, "kind": "use", "digest": DIGEST, "nonce": NONCE, "exp": 1760200600,
           "requester": {"device_id": "dev_srv", "label": "srv", "os": "linux", "protection": {"kind": "tpm2", "attestation": None, "future_status": "unverified"}},
           "agent": {"runtime": "claude-code", "cwd": "/home/u/proj", "user": "u", "pid": 4242},
           "credential": {"ref": "github/default", "kind": "oauth2", "display": "GitHub (test)", "proxy_only": True},
           "operation": {"summary": "POST issues · 15 B", "method": "POST", "host": "api.github.com", "path": "/repos/guang/demo/issues", "query_keys": ["a", "a", "z"], "body_bytes": 15},
           "purpose": "Create an issue", "tier": "T1", "min_level": "quick", "scope_options": OPTIONS, "requested_scope": "per_credential", "merged_count": 1,
           "delivery": {"mode": "silent", "escalate_after_s": 30}}
DECISION = {"approval_id": ID, "digest": DIGEST, "nonce": NONCE, "decision": "allow", "level": "quick",
            "scope": {"mode": "per_use", "level": "credential", "until": 0}, "approver": "dev_mac", "approver_kind": "device", "quorum": None,
            "issued_at": NOW, "future_binding": {"flag": True, "nullable": None}}


def decision_vector(name, decision, expect, record=APPROVER):
    write(name, {"keys": KEY_DATA, "request": REQUEST, "canonical": canonical_input, "device": record, "now": NOW, "decision": decision, "expect": expect})


decision_vector("decision_valid.json", signed(DECISION, KEYS["quick"]), {"ok": True})
decision_vector("decision_wrong_key.json", signed(DECISION, KEYS["wrong"]), {"error": "invalid_signature"})
decision_vector("decision_replayed.json", signed(DECISION, KEYS["quick"]), {"attempts": [{"ok": True}, {"error": "replay"}], "consumed": 1})
rs_decision = copy.deepcopy(DECISION); rs_decision["level"] = "strong"
decision_vector("rs256_decision.json", signed(rs_decision, RSA_KEY), {"ok": True}, device("recipient", True, True))

GRANT = {"kind": "grant", "jti": ID, "iss": "dev_mac", "iss_alg": "ES256", "iss_kind": "device", "aud": "dev_srv",
         "scope": {"level": "credential", "credential": "github/default", "hosts": ["api.github.com"], "methods": ["GET", "HEAD"], "max_tier": "T1"},
         "nbf": 1760200000, "exp": None, "origin": "settings", "future_policy": {"version": 2}}
write("grant_standing_t1.json", {"keys": KEY_DATA, "grant": signed(GRANT, KEYS["strong"]), "device": APPROVER, "level": "strong", "audience": "dev_srv", "audience_label": "srv", "now": NOW,
                               "expect": {"ok": True, "covers_t1": True, "covers_t2": False}})
t2 = copy.deepcopy(GRANT); t2["scope"]["max_tier"] = "T2"; t2["origin"] = "approval:" + ID; t2["exp"] = NOW + 604800
write("grant_t2_requires_settings.json", {"keys": KEY_DATA, "grant": signed(t2, KEYS["strong"]), "device": APPROVER, "level": "strong", "audience": "dev_srv", "audience_label": "srv", "now": NOW,
                                        "expect": {"error": "invalid_grant"}})


def directive(mode, key):
    return signed({"kind": "directive", "id": ID, "iss": "dev_mac", "iss_alg": "ES256", "iss_kind": "device", "aud": "dev_srv", "op": "set_mode",
                   "args": {"mode": mode, "future_option": None}, "nonce": NONCE, "exp": NOW + 300}, key)


write("directive_tighten_quick_ok.json", {"keys": KEY_DATA, "directive": directive("per_use", KEYS["quick"]), "device": APPROVER, "level": "quick", "audience": "dev_srv", "now": NOW,
                                        "current": {"mode": "per_credential"}, "expect": {"ok": True}})
write("directive_loosen_quick_rejected.json", {"keys": KEY_DATA, "directive": directive("per_session", KEYS["quick"]), "device": APPROVER, "level": "quick", "audience": "dev_srv", "now": NOW,
                                             "current": {"mode": "per_use"}, "expect": {"error": "insufficient_level"}})

token = bytes(range(16))
sas_input = b"keyvalet-pair-v1" + token + b"".join(sorted([canonical(SERVER["dk_pub"]), canonical(APPROVER["dk_pub"])])) + canonical(pub(KEYS["quick"])) + canonical(pub(KEYS["strong"]))
SAS = str(int.from_bytes(hashlib.sha256(sas_input).digest(), "big")).zfill(6)[:6]
CONFIRM = signed({"sas": SAS}, KEYS["strong"])
write("pair_sas.json", {"keys": KEY_DATA, "token": b64(token), "initiator": SERVER, "joiner": APPROVER, "confirm": CONFIRM,
                       "expect": {"sas": SAS, "swapped_sas": SAS, "confirm_ok": True}})


def point(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def extract(suite, salt, label, ikm):
    return hmac.new(salt or bytes(32), b"HPKE-v1" + suite + label + ikm, hashlib.sha256).digest()


def expand(suite, prk, label, info, length):
    context = length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info
    previous, result = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(prk, previous + context + bytes([i]), hashlib.sha256).digest(); result += previous
    return result[:length]


HEADER = {"v": 1, "type": "approval_request", "id": ID, "account": "acct_test", "from": "dev_srv", "to": "dev_mac", "created_at": 1760200000, "exp": 1760200600}
aad = canonical(HEADER)
dh = KEYS["ephemeral"].exchange(ec.ECDH(), KEYS["recipient"].public_key())
kem_suite, suite = b"KEM\x00\x10", b"HPKE\x00\x10\x00\x01\x00\x01"
shared = expand(kem_suite, extract(kem_suite, b"", b"eae_prk", dh), b"shared_secret", point(KEYS["ephemeral"]) + point(KEYS["recipient"]), 32)
context = b"\0" + extract(suite, b"", b"psk_id_hash", b"") + extract(suite, b"", b"info_hash", b"keyvalet/envelope/v1")
secret = extract(suite, shared, b"secret", b"")
key = expand(suite, secret, b"key", context, 16); nonce = expand(suite, secret, b"base_nonce", context, 12)
plaintext = canonical(REQUEST)
ct = AESGCM(key).encrypt(nonce, plaintext, aad)
ENVELOPE = {**HEADER, "enc": b64(point(KEYS["ephemeral"])), "ct": b64(ct), "sig": b64(sign_bytes(KEYS["sender"], aad + ct))}
write("envelope_roundtrip.json", {"keys": KEY_DATA, "header": HEADER, "sender": SERVER, "recipient": APPROVER, "plaintext": plaintext.decode(), "envelope": ENVELOPE, "now": NOW,
                                 "expect": {"aad": aad.decode(), "ciphertext_len": len(ct), "enc": ENVELOPE["enc"], "ct": ENVELOPE["ct"], "plaintext": plaintext.decode(), "signature_ok": True}})

# K1: dedicated identity ECDSA key; all original keys/vectors above remain byte-identical.
SPLIT_DEVICE = copy.deepcopy(APPROVER)
SPLIT_DEVICE.update(os="windows", label="Windows fixture", dk_sig={"pub": pub(KEYS["wrong"]), "alg": "ES256", "future_key": {"binding": "signed"}})
SPLIT_PROOF = {"action": "device_record", "device": SPLIT_DEVICE, "future_proof": {"v": 1}}
split_payload = canonical(SPLIT_PROOF)
split_signature = b64(sign_bytes(KEYS["wrong"], split_payload))
write("device_record_with_dk_sig_valid.json", {"device": SPLIT_DEVICE, "proof": SPLIT_PROOF,
    "payload": split_payload.decode(), "sig": split_signature,
    "expect": {"ok": True, "canonical": canonical(SPLIT_DEVICE).decode(), "digest": hashlib.sha256(canonical(SPLIT_DEVICE)).hexdigest()}})
write("device_record_with_dk_sig_wrong_dk.json", {"device": SPLIT_DEVICE, "payload": split_payload.decode(), "sig": split_signature,
    "expect": {"identity_ok": True, "dk_error": "invalid_signature"}})
changed = copy.deepcopy(SPLIT_PROOF)
changed["device"]["dk_sig"]["future_key"]["binding"] = "tampered"
write("device_record_with_dk_sig_tampered.json", {"device": SPLIT_DEVICE, "proof": changed, "sig": split_signature,
    "expect": {"error": "invalid_signature"}})
legacy_proof = {"action": "device_record", "device": APPROVER}
write("device_record_with_dk_sig_legacy.json", {"device": APPROVER, "proof": legacy_proof, "sig": b64(sign_bytes(KEYS["recipient"], canonical(legacy_proof))),
    "expect": {"ok": True, "canonical": canonical(APPROVER).decode()}})
# Identity selection also applies to the envelope, independently of its HPKE recipient key.
split_envelope = copy.deepcopy(ENVELOPE)
split_envelope["sig"] = b64(sign_bytes(KEYS["wrong"], aad + ct))
split_sender = copy.deepcopy(SERVER)
split_sender["dk_sig"] = copy.deepcopy(SPLIT_DEVICE["dk_sig"])
write("device_record_with_dk_sig_envelope.json", {"sender": split_sender, "recipient": APPROVER, "envelope": split_envelope, "now": NOW,
    "expect": {"open_ok": True, "plaintext": plaintext.decode(), "dk_error": "invalid_signature"}})

official_url = "https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json"
official_path = HERE / "rfc9180_p256_base.json"
if official_path.exists():
    official = json.loads(official_path.read_text())
else:
    data = json.load(urllib.request.urlopen(official_url, timeout=30))
    official = next(v for v in data if (v["mode"], v["kem_id"], v["kdf_id"], v["aead_id"]) == (0, 16, 1, 1))
    expected = {k: official.pop(k) for k in ["enc", "shared_secret", "key", "base_nonce", "secret", "key_schedule_context", "exporter_secret"]}
    expected.update(pkEm=official["pkEm"], pkRm=official["pkRm"], received_shared_secret=expected["shared_secret"], reference_enc=expected["enc"],
                    derived_skEm=official["skEm"], derived_pkEm=official["pkEm"], derived_skRm=official["skRm"], derived_pkRm=official["pkRm"])
    expected["encryptions"] = [{"nonce": e["nonce"], "ct": e["ct"], "reference_ct": e["ct"], "pt": e["pt"], "reference_pt": e["pt"]} for e in official["encryptions"]]
    expected["exports"] = [{"exported_value": e["exported_value"], "reference_exported_value": e["exported_value"]} for e in official["exports"]]
    official["expect"] = expected; official["source"] = official_url
write("rfc9180_p256_base.json", official)

# Standalone schemas include only the transitive definitions needed by that object.
DEFS, SAMPLES, RUST_TYPES = {}, {}, {}
STRING = {"type": "string"}
BOOL = {"type": "boolean"}
INT = {"type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}
UINT = {"type": "integer", "minimum": 0, "maximum": 9007199254740991}
U32 = {"type": "integer", "minimum": 0, "maximum": 4294967295}
ULID = {"type": "string", "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"}
B64 = {"type": "string", "pattern": "^[A-Za-z0-9_-]*$"}
HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
NONCE_SCHEMA = {"type": "string", "pattern": "^[A-Za-z0-9_-]{22}$"}
OBJECT = {"type": "object"}


def ref(name): return {"$ref": "#/$defs/" + name}
def array(item): return {"type": "array", "items": item}
def enum(*values): return {"enum": list(values)}
def nullable(schema): return {"anyOf": [schema, {"type": "null"}]}
def snake(name): return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def obj(name, props, sample, optional=(), rust=None, rules=None):
    DEFS[name] = {"type": "object", "properties": props, "required": [p for p in props if p not in optional], "additionalProperties": True}
    if rules: DEFS[name].update(rules)
    SAMPLES[name] = sample
    RUST_TYPES[name] = rust or name


obj("PublicJwk", {"kty": STRING, **{k: STRING for k in ["crv", "x", "y", "n", "e"]}}, pub(KEYS["sender"]), ["crv", "x", "y", "n", "e"], rules={
    "anyOf": [{"properties": {"kty": {"const": "EC"}, "crv": {"const": "P-256"}, "x": {"type": "string", "minLength": 43, "maxLength": 43}, "y": {"type": "string", "minLength": 43, "maxLength": 43}}, "required": ["crv", "x", "y"]},
              {"properties": {"kty": {"const": "RSA"}}, "required": ["n", "e"]}],
    "not": {"anyOf": [{"required": [k]} for k in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]]}})
obj("ApprovalKey", {"pub": ref("PublicJwk"), "alg": enum("ES256", "RS256")}, APPROVER["ak_q"])
obj("Attestation", {"kind": STRING, "doc": {}}, {"kind": "future-attestation", "doc": {"opaque": "test"}, "future": 1})
identity_sign_schema = {"type": "object", "properties": {"pub": {"allOf": [ref("PublicJwk"), {"properties": {"kty": {"const": "EC"}, "crv": {"const": "P-256"}}}]}, "alg": {"const": "ES256"}}, "required": ["pub", "alg"], "additionalProperties": True}
obj("DeviceRecord", {"device_id": STRING, "label": STRING, "os": STRING, "key_kind": STRING, "dk_pub": ref("PublicJwk"), "dk_sig": identity_sign_schema, "ak_q": nullable(ref("ApprovalKey")), "ak_s": nullable(ref("ApprovalKey")), "caps": array(STRING), "attestation": nullable(ref("Attestation"))}, APPROVER, ["dk_sig"])
obj("Protection", {"kind": STRING, "attestation": nullable(ref("Attestation"))}, REQUEST["requester"]["protection"], ["attestation"])
obj("Requester", {"device_id": STRING, "label": STRING, "os": STRING, "protection": ref("Protection")}, REQUEST["requester"])
obj("Agent", {"runtime": STRING, "cwd": STRING, "user": STRING, "pid": U32}, REQUEST["agent"])
obj("Credential", {"ref": STRING, "kind": STRING, "display": STRING, "proxy_only": BOOL}, REQUEST["credential"])
obj("Operation", {"summary": STRING, "method": STRING, "host": STRING, "path": STRING, "query_keys": array(STRING), "body_bytes": UINT}, REQUEST["operation"])
obj("Delivery", {"mode": enum("banner", "silent"), "escalate_after_s": U32}, REQUEST["delivery"])
header_props = {"v": U32, "type": STRING, "id": ULID, "account": STRING, "from": STRING, "to": STRING, "created_at": INT, "exp": INT}
obj("EnvelopeHeader", header_props, HEADER)
obj("Envelope", {**header_props, "enc": B64, "ct": B64, "sig": B64}, ENVELOPE)
obj("ApprovalRequest", {"approval_id": ULID, "kind": enum("unlock", "use", "admin"), "digest": HEX, "nonce": NONCE_SCHEMA, "exp": INT,
                       "requester": ref("Requester"), "agent": ref("Agent"), "credential": nullable(ref("Credential")), "operation": nullable(ref("Operation")),
                       "purpose": STRING, "tier": enum("T0", "T1", "T2"), "min_level": enum("quick", "strong"), "scope_options": array(enum(*OPTIONS)),
                       "requested_scope": enum(*OPTIONS), "merged_count": {"type": "integer", "minimum": 1, "maximum": 4294967295}, "delivery": ref("Delivery")}, REQUEST, rules={"allOf": [
    {"if": {"properties": {"kind": {"const": "unlock"}}}, "then": {"properties": {"credential": {"type": "null"}, "operation": {"type": "null"}, "min_level": {"const": "strong"}}}},
    {"if": {"properties": {"kind": {"const": "use"}}}, "then": {"properties": {"credential": ref("Credential"), "operation": ref("Operation")}}},
    {"if": {"properties": {"kind": {"const": "admin"}}}, "then": {"properties": {"min_level": {"const": "strong"}, "operation": ref("Operation")}}},
    {"if": {"properties": {"tier": {"const": "T2"}}}, "then": {"properties": {"scope_options": {"const": ["per_use"]}, "requested_scope": {"const": "per_use"}, "min_level": {"const": "strong"}}}}]})
obj("DecisionScope", {"mode": enum("per_use", "per_credential", "per_session", "remember", "standing"), "level": enum("credential", "device"), "until": INT}, DECISION["scope"])
obj("Quorum", {"m": U32, "n": U32, "sigs": array({})}, {"m": 2, "n": 3, "sigs": [{"future": "opaque"}]})
obj("ApprovalDecision", {"approval_id": ULID, "digest": HEX, "nonce": B64, "decision": enum("allow", "deny"), "level": enum("quick", "strong"), "scope": ref("DecisionScope"), "approver": STRING,
                        "approver_kind": STRING, "quorum": nullable(ref("Quorum")), "issued_at": INT, "reason": nullable(STRING), "sig": B64}, signed(DECISION, KEYS["quick"]), ["quorum", "reason"])
obj("GrantScope", {"level": enum("credential", "device", "global"), "credential": nullable(STRING), "hosts": nullable(array(STRING)), "methods": nullable(array(STRING)), "paths": nullable(array(STRING)), "agent": nullable(STRING), "max_tier": enum("T0", "T1", "T2")}, GRANT["scope"], ["credential", "hosts", "methods", "paths", "agent"], rules={
    "if": {"properties": {"level": {"const": "credential"}}}, "then": {"required": ["credential"], "properties": {"credential": STRING}}})
obj("Budget", {"calls": UINT, "per": enum("1h", "24h", "7d"), "bytes": nullable(UINT)}, {"calls": 500, "per": "24h"}, ["bytes"])
grant_props = {"kind": {"const": "grant"}, "jti": ULID, "iss": STRING, "iss_alg": enum("ES256", "RS256"), "iss_kind": STRING, "aud": STRING, "scope": ref("GrantScope"),
               "budget": nullable(ref("Budget")), "nbf": INT, "exp": nullable(INT), "origin": STRING, "confirm": nullable(STRING), "sig": B64}
grant_rules = {"allOf": [
    {"if": {"properties": {"scope": {"properties": {"level": {"const": "global"}}}}}, "then": {"properties": {"aud": {"const": "*"}}}},
    {"if": {"properties": {"scope": {"properties": {"max_tier": {"const": "T2"}}}}}, "then": {"properties": {"origin": {"const": "settings"}}, "anyOf": [{"properties": {"exp": INT}}, {"required": ["confirm"], "properties": {"confirm": STRING}}]}}]}
obj("Grant", grant_props, signed(GRANT, KEYS["strong"]), ["budget", "confirm"], rules=grant_rules)
obj("UnsignedGrant", {k: v for k, v in grant_props.items() if k != "sig"}, GRANT, ["budget", "confirm"], "ipc::Unsigned<Grant>", {**grant_rules, "not": {"required": ["sig"]}})
obj("EmptyArgs", {}, {})
obj("SetModeArgs", {"mode": STRING}, {"mode": "per_use"})
obj("RevokeGrantArgs", {"jti": ULID}, {"jti": ID})
obj("SetUnlockTtlArgs", {"seconds": {"type": "integer", "minimum": 1, "maximum": 86400}}, {"seconds": 43200})
obj("SetClassArgs", {"name": STRING, "match": OBJECT, "exp_s": {"type": "integer", "minimum": 1, "maximum": 86400}}, {"name": "batch", "match": {"host": "api.openai.com"}, "exp_s": 86400})
obj("SetDeviceLabelArgs", {"label": STRING}, {"label": "srv"})
obj("RevokeDeviceArgs", {"device_id": STRING}, {"device_id": "dev_mac"})
obj("NotifyArgs", {"policy": enum("prefer-local", "always-phone", "both")}, {"policy": "always-phone"})
obj("QueryAuditArgs", {"since": INT, "limit": {"type": "integer", "minimum": 0, "maximum": 200}, "after": UINT, "through": UINT}, {"since": NOW, "limit": 200}, ["after","through"])
obj("CancelApprovalArgs", {"approval_id": ULID}, {"approval_id": ID})
OP_ARGS = {"set_mode": "SetModeArgs", "revoke_grant": "RevokeGrantArgs", "revoke_all_grants": "EmptyArgs", "lock": "EmptyArgs", "set_unlock_ttl": "SetUnlockTtlArgs",
           "set_class": "SetClassArgs", "set_device_label": "SetDeviceLabelArgs", "revoke_device": "RevokeDeviceArgs", "notify": "NotifyArgs", "query_status": "EmptyArgs", "query_pending": "EmptyArgs", "query_grants": "EmptyArgs", "query_audit": "QueryAuditArgs", "cancel_approval": "CancelApprovalArgs"}
directive_props = {"kind": {"const": "directive"}, "id": ULID, "iss": STRING, "iss_alg": enum("ES256", "RS256"), "iss_kind": STRING, "aud": STRING,
                   "op": enum(*OP_ARGS), "args": OBJECT, "nonce": NONCE_SCHEMA, "exp": INT, "sig": B64}
directive_rules = {"allOf": [{"if": {"properties": {"op": {"const": op}}}, "then": {"properties": {"args": ref(arg)}}} for op, arg in OP_ARGS.items()]}
obj("Directive", directive_props, directive("per_use", KEYS["quick"]), rules=directive_rules)
unsigned_directive = directive("per_use", KEYS["quick"]); unsigned_directive.pop("sig")
obj("UnsignedDirective", {k: v for k, v in directive_props.items() if k != "sig"}, unsigned_directive, rust="ipc::Unsigned<Directive>", rules={**directive_rules, "not": {"required": ["sig"]}})
RESULT = {"id": ID, "ok": True, "error": None, "state": {"mode": "per_use"}}
obj("DirectiveResult", {"id": ULID, "ok": BOOL, "error": nullable(STRING), "state": OBJECT}, RESULT)
HINT = {"device_id": "dev_mac", "state": "present", "since": NOW, "sent_at": NOW}
obj("PresenceHint", {"device_id": STRING, "state": enum("present", "idle", "away"), "since": INT, "sent_at": INT}, HINT)
obj("PairOffer", {"token_hash": HEX, "initiator": ref("DeviceRecord")}, {"token_hash": hashlib.sha256(token).hexdigest(), "initiator": SERVER})
obj("PairAccept", {"token": NONCE_SCHEMA, "joiner": ref("DeviceRecord")}, {"token": b64(token), "joiner": APPROVER})
obj("PairConfirm", {"sas": {"type": "string", "pattern": "^[0-9]{6}$"}, "sig": B64}, CONFIRM)
obj("ApprovalEscalate", {"approval_id": ULID}, {"approval_id": ID})
obj("ApprovalCancel", {"approval_id": ULID}, {"approval_id": ID})
obj("DeviceRevoke", {"device_id": STRING}, {"device_id": "dev_mac"})
obj("ToolApprover", {"label": STRING, "online": BOOL}, {"label": "MacBook", "online": False})
TOOL = {"status": "approval_pending", "approval_id": ID, "expires_at": NOW + 300, "approver": SAMPLES["ToolApprover"], "wait_tool": "credential_wait_approval", "next_steps": "Wait for this approval without sending a duplicate request."}
obj("ToolResult", {"status": enum("ok", "approval_pending", "approval_denied", "approval_expired", "no_approver", "approved_retry_required", "still_pending", "already_consumed"), "approval_id": nullable(ULID), "expires_at": nullable(INT), "approver": nullable(ref("ToolApprover")), "wait_tool": nullable({"const": "credential_wait_approval"}), "next_steps": nullable(STRING), "result": {}}, TOOL,
    ["approval_id", "expires_at", "approver", "wait_tool", "next_steps", "result"], rules={"if": {"properties": {"status": {"const": "ok"}}}, "else": {"not": {"required": ["result"]}}})
obj("CanonicalAction", {"kind": STRING}, canonical_input["action"], rust="canonical::CanonicalAction")
obj("CanonicalAgent", {"runtime": STRING, "repo_or_cwd": STRING, "uid": U32, "pid": U32, "exe_sha256": HEX}, canonical_input["agent"], rust="canonical::CanonicalAgent")
obj("CanonicalRequest", {"v": {"const": 1}, "kind": enum("unlock", "use", "admin"), "requester": STRING, "credential": nullable(STRING), "action": ref("CanonicalAction"), "method": nullable(STRING), "host": nullable(STRING), "path": nullable(STRING), "query_keys": array(STRING), "body_sha256": nullable(HEX), "headers_digest": nullable(HEX), "agent": ref("CanonicalAgent"), "purpose": STRING, "nonce": NONCE_SCHEMA, "exp": INT}, canonical_input, rust="canonical::CanonicalRequest")
signals = {"graphical_session": True, "session_active": True, "screen_locked": False, "screensaver_active": False, "idle_seconds": 1, "display_connected": True, "display_awake": True, "remote_session_active": False, "approval_channel_available": True}
obj("PresenceSignals", {k: nullable(UINT if k == "idle_seconds" else BOOL) for k in signals}, signals, rust="traits::PresenceSignals")
obj("PresenceState", {"state": enum("present", "idle", "away"), "since": INT, "signals": ref("PresenceSignals")}, {"state": "present", "since": NOW, "signals": signals}, rust="traits::PresenceState")

# Appendix B objects.
obj("RegisterDeviceRequest", {**DEFS["DeviceRecord"]["properties"], "push_token": {}}, {**APPROVER, "push_token": {"provider": "apns", "token": "test-token"}}, ["push_token", "dk_sig"], "relay::RegisterDeviceRequest")
obj("RegisterDeviceResponse", {"account_id": STRING, "device_id": STRING, "recovery_code": nullable(STRING)}, {"account_id": "acct_test", "device_id": "dev_mac"}, ["recovery_code"], "relay::RegisterDeviceResponse")
relay_objects = {
    "ChallengeRequest": ({"device_id": STRING}, {"device_id": "dev_srv"}),
    "ChallengeResponse": ({"challenge": B64, "exp": INT}, {"challenge": b64(bytes(32)), "exp": NOW + 60}),
    "AuthVerifyRequest": ({"device_id": STRING, "challenge": B64, "sig": B64}, {"device_id": "dev_srv", "challenge": b64(bytes(32)), "sig": ENVELOPE["sig"]}),
    "AuthVerifyResponse": ({"session_token": B64, "exp": INT}, {"session_token": b64(bytes(32)), "exp": NOW + 86400}),
    "RelayPairStartRequest": ({"token_hash": HEX, "initiator": ref("DeviceRecord"), "exp": INT}, {"token_hash": hashlib.sha256(token).hexdigest(), "initiator": SERVER, "exp": NOW + 600}),
    "RelayPairStartResponse": ({"pairing_id": ULID}, {"pairing_id": ID}),
    "RelayPairCompleteRequest": ({"token": NONCE_SCHEMA, "joiner": ref("DeviceRecord")}, {"token": b64(token), "joiner": APPROVER}),
    "RelayPairCompleteResponse": ({"pairing_id": ULID, "initiator": ref("DeviceRecord")}, {"pairing_id": ID, "initiator": SERVER}),
    "PairFinishRequest": ({"pairing_id": ULID, "confirm": ref("PairConfirm")}, {"pairing_id": ID, "confirm": CONFIRM}),
    "SubmitApprovalsRequest": ({"id": ULID, "exp": INT, "envelopes": array(ref("Envelope"))}, {"id": ID, "exp": NOW + 300, "envelopes": [ENVELOPE]}),
    "ReplyApprovalRequest": ({"envelope": ref("Envelope")}, {"envelope": ENVELOPE}),
    "EnvelopesResponse": ({"envelopes": array(ref("Envelope"))}, {"envelopes": [ENVELOPE]}),
    "SendMessagesRequest": ({"envelopes": array(ref("Envelope"))}, {"envelopes": [ENVELOPE]}),
    "AckMessagesRequest": ({"ids": array(ULID), "type": {"type": "string"}}, {"ids": [ID]}),
    "AcceptedResponse": ({"accepted": UINT}, {"accepted": 1}), "OkResponse": ({"ok": BOOL}, {"ok": True}),
    "HealthResponse": ({"ok": BOOL, "version": STRING}, {"ok": True, "version": "0.3.0"}),
    "RelayError": ({"code": enum("unauthorized", "forbidden", "not_found", "rate_limited", "payload_too_large", "bad_envelope", "expired", "conflict"), "message": STRING}, {"code": "forbidden", "message": "Access denied"}),
    "RelayErrorResponse": ({"error": ref("RelayError")}, {"error": {"code": "forbidden", "message": "Access denied"}}),
}
for name, (props, sample) in relay_objects.items():
    rust_name = name.removeprefix("Relay")
    obj(name, props, sample, optional=("type",) if name == "AckMessagesRequest" else (), rust="relay::" + rust_name)
DEFS["RelayPairCompleteResponse"]["properties"]["account_id"] = nullable(STRING)
SAMPLES["RelayPairCompleteResponse"]["account_id"] = "acct_test"
obj("DeleteDeviceRequest", {"by": enum("device", "recovery"), "recovery_code": nullable(STRING)}, {"by": "device"}, ["recovery_code"], "relay::DeleteDeviceRequest")
obj("DeviceDeleteProof", {"action": {"const":"revoke_device"}, "account":STRING, "by":STRING, "device_id":STRING, "challenge":B64}, {"action":"revoke_device", "account":"acct_test", "by":"dev_mac", "device_id":"dev_srv", "challenge":b64(bytes(32))}, rust="relay::DeviceDeleteProof")
DEFS["WsFrame"] = {"oneOf": [{"type": "object", "properties": {"t": {"const": t}, **extra}, "required": ["t", *extra], "additionalProperties": True} for t, extra in [("ping", {}), ("pong", {}), ("ack", {"id": ULID}), ("envelope", {"envelope": ref("Envelope")}), ("pair_accept", {"pairing_id":ULID,"joiner":ref("DeviceRecord")}), ("approval_cancel", {"id":ULID})]]}
SAMPLES["WsFrame"], RUST_TYPES["WsFrame"] = {"t": "envelope", "envelope": ENVELOPE}, "relay::WsFrame"
relay_extensions = [
    {"type":"RelayPairCompleteResponse", "schema":"relay_pair_complete_response.schema.json", "value":SAMPLES["RelayPairCompleteResponse"]},
    {"type":"WsFrame", "schema":"ws_frame.schema.json", "value":{"t":"pair_accept", "pairing_id":ID, "joiner":APPROVER, "future":True}},
    {"type":"WsFrame", "schema":"ws_frame.schema.json", "value":{"t":"approval_cancel", "id":ID, "future":None}},
    {"type":"DeviceDeleteProof", "schema":"device_delete_proof.schema.json", "value":SAMPLES["DeviceDeleteProof"]},
    {"type":"DeviceDeleteProof", "schema":"device_delete_proof.schema.json", "value":{**SAMPLES["DeviceDeleteProof"], "action":"future_action"}},
]
write("relay_contract_extensions.json", {"cases":relay_extensions, "expect":[{"roundtrip":True,"schema_valid":True}] * 4 + [{"roundtrip":False,"schema_valid":False}]})

# Appendix C generic payloads are concretized by kv-core aliases.
ipc_objects = {
    "IpcEmpty": ({}, {}), "IpcError": ({"code": STRING, "message": STRING}, {"code": "forbidden", "message": "Access denied"}),
    "RelayInboundParams": ({"envelope": ref("Envelope")}, {"envelope": ENVELOPE}),
    "RelayInboundResult": ({"ack": {"const": True}}, {"ack": True}),
    "RelayOutboundPollParams": ({"max_wait_ms": UINT}, {"max_wait_ms": 1000}),
    "RelayOutboundPollResult": ({"envelopes": array(ref("Envelope"))}, {"envelopes": [ENVELOPE]}),
    "RelayStatusParams": ({"connected": BOOL, "last_error": nullable(STRING), "since": INT}, {"connected": True, "last_error": None, "since": NOW}),
    "SignIdentityParams": ({"payload_b64": B64}, {"payload_b64": b64(bytes(32))}), "SignIdentityResult": ({"sig_b64": B64}, {"sig_b64": ENVELOPE["sig"]}),
    "PendingForAgentParams": ({"agent_pid": U32}, {"agent_pid": 4242}), "ApprovalIdParams": ({"approval_id": ULID}, {"approval_id": ID}),
    "PendingStopBlockResult": ({"allowed": BOOL, "blocks_left": U32}, {"allowed": True, "blocks_left": 2}),
    "WaitParams": ({"approval_id": ULID, "max_wait_ms": UINT}, {"approval_id": ID, "max_wait_ms": 5000}),
    "GrantRevokeParams": ({"jti": ULID}, {"jti": ID}), "DeviceIdParams": ({"device_id": STRING}, {"device_id": "dev_mac"}),
    "DeviceRenameParams": ({"device_id": STRING, "label": STRING}, {"device_id": "dev_mac", "label": "Laptop"}), "PairSasResult": ({"sas": STRING}, {"sas": SAS}),
    "PendingForAgentEntry": ({"approval_id": ULID, "expires_at": INT, "stop_hook_blocks": U32}, {"approval_id": ID, "expires_at": NOW + 300, "stop_hook_blocks": 0}),
    "PendingForAgentResult": ({"pending": array(ref("PendingForAgentEntry"))}, {"pending": [{"approval_id": ID, "expires_at": NOW + 300, "stop_hook_blocks": 0}]}),
    "StatusApprover": ({"label": STRING, "online": BOOL}, {"label": "MacBook", "online": True}),
    "StatusResult": ({"relay": enum("connected", "offline"), "approvers": array(ref("StatusApprover")), "pending_n": UINT, "grants_n": UINT, "unattended": BOOL, "runtime_budget_s": U32}, {"relay": "connected", "approvers": [], "pending_n": 1, "grants_n": 0, "unattended": False, "runtime_budget_s": 60}),
    "PendingListResult": ({"pending": array(ref("ApprovalRequest"))}, {"pending": [REQUEST]}),
    "DecideParams": ({"approval_id": ULID, "decision": enum("allow", "deny"), "scope": ref("DecisionScope"), "level": enum("quick", "strong")}, {"approval_id": ID, "decision": "allow", "scope": DECISION["scope"], "level": "quick"}),
    "DecideResult": ({"sent": {"const": True}}, {"sent": True}),
    "GrantIssueResult": ({"grant": ref("Grant")}, {"grant": signed(GRANT, KEYS["strong"])}),
    "GrantListResult": ({"grants": array(ref("Grant"))}, {"grants": [signed(GRANT, KEYS["strong"])]}),
    "DirectiveIssueResult": ({"result": ref("DirectiveResult")}, {"result": RESULT}),
    "DevicesListResult": ({"devices": array(ref("DeviceRecord"))}, {"devices": [APPROVER]}),
}
concrete = {"RelayInboundParams", "RelayOutboundPollResult", "PendingListResult", "DecideParams", "GrantIssueResult", "GrantListResult", "DirectiveIssueResult", "DevicesListResult"}
for name, (props, sample) in ipc_objects.items(): obj(name, props, sample, rust=("ipc::" + name if name in concrete else "kv_ipc::remote::" + name.removeprefix("Ipc")))
obj("PendingListParams", {"agent_pid": U32}, {}, ["agent_pid"], "kv_ipc::remote::PendingListParams")
# Owner intents are projections, not signed Appendix A objects; issuer fields are rejected.
owner_objects = {
    "DecideIntent": ({"approval_id": ULID, "decision": enum("allow", "deny"), "scope": ref("DecisionScope"), "scope_option": nullable(STRING), "level": nullable(enum("quick", "strong")), "reason": nullable(STRING)}, {"approval_id": ID, "decision": "allow", "scope": DECISION["scope"], "scope_option": "per_use"}, ["scope_option", "level", "reason"]),
    "GrantIntent": ({"source": enum("preauthorization", "settings"), "kind": enum("grant"), "aud": STRING, "scope": ref("GrantScope"), "budget": nullable(ref("Budget")), "nbf": INT, "exp": nullable(INT), "origin": STRING, "confirm": nullable(STRING), "confirmation_token": nullable(STRING)}, {"source": "settings", "kind": "grant", "aud": "dev_srv", "scope": GRANT["scope"], "nbf": NOW, "exp": NOW + 3600, "origin": "settings"}, ["budget", "confirm", "confirmation_token"]),
    "GrantConfirmation": ({"confirmation_token": STRING, "expires_at": INT, "device_id": STRING, "label": STRING, "confirmations_left": {"type": "integer", "minimum": 0, "maximum": 255, "default": 1}}, {"confirmation_token": "test-only-one-use-token", "expires_at": NOW + 120, "device_id": "dev_srv", "label": "srv", "confirmations_left": 1}, ["confirmations_left"]),
    "DirectiveIntent": ({"kind": enum("directive"), "aud": STRING, "op": enum(*OP_ARGS), "args": OBJECT}, {"kind": "directive", "aud": "dev_srv", "op": "lock", "args": {}}, []),
    "PairJoinIntent": ({"uri": STRING}, {"uri": "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA"}, []),
    "PairConfirmIntent": ({"sas": STRING, "confirmed": BOOL}, {"sas": SAS, "confirmed": True}, []),
    "RelayBinding": ({"relay_url": STRING, "device_id": STRING, "account_id": STRING}, {"relay_url": "https://relay.example.com", "device_id": "dev_mac", "account_id": "acct_test"}, []),
}
owner_cases, owner_expect = [], []
for name, (props, sample, optional) in owner_objects.items():
    obj(name, props, sample, optional, "ipc::" + name, {"additionalProperties": False})
    owner_cases.append({"type": name, "schema": snake(name) + ".schema.json", "value": sample})
    owner_expect.append({"roundtrip": True, "schema_valid": True})
    owner_cases.append({"type": name, "schema": snake(name) + ".schema.json", "value": {**sample, "iss": "caller-chosen-issuer"}})
    owner_expect.append({"roundtrip": False, "schema_valid": False})
DEFS["GrantSource"], SAMPLES["GrantSource"], RUST_TYPES["GrantSource"] = enum("preauthorization", "settings"), "settings", "ipc::GrantSource"
write("owner_intent_contracts.json", {"cases": owner_cases, "expect": owner_expect})
obj("RecoverAccountRequest", {"account_id": STRING, "recovery_code": {"type":"string","minLength":43,"maxLength":43}, "new_recovery_code": {"type":"string","minLength":43,"maxLength":43}, "device": ref("DeviceRecord"), "nonce": {"type":"string","minLength":43,"maxLength":43}, "sig": {"type":"string","minLength":86,"maxLength":86}}, {"account_id":"acct_test","recovery_code":"A"*43,"new_recovery_code":"B"*43,"device":SERVER,"nonce":"A"*43,"sig":"A"*86}, rules={"additionalProperties":False}, rust="relay::RecoverAccountRequest")
obj("RecoverAccountResponse", {"ok":{"const":True},"account_id":STRING,"device_id":STRING,"recovery_code":{"type":"string","minLength":43,"maxLength":43}}, {"ok":True,"account_id":"acct_test","device_id":"dev_srv","recovery_code":"A"*43}, rules={"additionalProperties":False}, rust="relay::RecoverAccountResponse")
OPS = ["remote.relay.inbound", "remote.relay.outbound.poll", "remote.relay.status", "remote.sign_identity", "remote.presence.update", "remote.pending.list", "remote.pending.for_agent", "remote.pending.stop_block", "remote.wait", "remote.decide", "remote.grant.issue", "remote.grant.list", "remote.grant.revoke", "remote.directive.issue", "remote.pair.start", "remote.pair.complete", "remote.pair.confirm", "remote.account.recover", "remote.devices.list", "remote.devices.revoke", "remote.devices.rename", "remote.status", "remote.audit.list", "remote.relay.identity", "remote.relay.outbound.ack", "remote.relay.control.poll", "remote.relay.control.complete", "remote.relay.control.sign", "remote.client_timeout_observed"]
obj("IpcRequest", {"op": enum(*OPS), "params": OBJECT}, {"op": "remote.relay.inbound", "params": SAMPLES["RelayInboundParams"]}, rust="kv_ipc::remote::Request")
DEFS["IpcResponse"] = {"oneOf": [{"type": "object", "properties": {"ok": {"const": True}, "result": {}}, "required": ["ok", "result"], "additionalProperties": True},
                                 {"type": "object", "properties": {"ok": {"const": False}, "error": ref("IpcError")}, "required": ["ok", "error"], "additionalProperties": True}]}
SAMPLES["IpcResponse"], RUST_TYPES["IpcResponse"] = {"ok": True, "result": {}}, "kv_ipc::remote::Response"


def refs(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref": yield item.removeprefix("#/$defs/")
            else: yield from refs(item)
    elif isinstance(value, list):
        for item in value: yield from refs(item)


for name, definition in DEFS.items():
    needed, todo = {}, list(refs(definition))
    while todo:
        dependency = todo.pop()
        if dependency not in needed:
            needed[dependency] = DEFS[dependency]; todo.extend(refs(DEFS[dependency]))
    document = {"$schema": "http://json-schema.org/draft-07/schema#", "title": name, **definition}
    if needed: document["$defs"] = needed
    (SCHEMAS / (snake(name) + ".schema.json")).write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
write("schema_samples.json", {"samples": [{"type": name, "schema": snake(name) + ".schema.json", "value": value} for name, value in SAMPLES.items()],
                             "expect": {"schemas": len(DEFS), "samples": {name: {"valid": True, "roundtrip": True, "extra_roundtrip": isinstance(value, dict) and name not in owner_objects and name not in ["RecoverAccountRequest", "RecoverAccountResponse"]} for name, value in SAMPLES.items()}}})

# Rust deserialization dispatch is generated from the same explicit fixture inventory.
dispatch = ["use kv_core::remote::*;", "use serde_json::Value;", "", "pub fn roundtrip(name: &str, value: Value) -> kv_core::remote::Result<Value> {", "    match name {"]
for name, rust in RUST_TYPES.items():
    dispatch.append(f'        "{name}" => encode::<{rust}>(value),')
dispatch += ['        _ => Err(RemoteError::InvalidJson),', '    }', '}', '',
             'fn encode<T: serde::de::DeserializeOwned + serde::Serialize>(value: Value) -> kv_core::remote::Result<Value> {',
             '    let decoded: T = serde_json::from_value(value).map_err(|_| RemoteError::InvalidJson)?;',
             '    serde_json::to_value(decoded).map_err(|_| RemoteError::InvalidJson)', '}']
support = CORE / "tests" / "remote_support"; support.mkdir(exist_ok=True)
(support / "schemas.rs").write_text("\n".join(dispatch) + "\n")

# Canonicalization and parser rejection vectors, including the RFC 8785 examples.
jcs_cases = [
    ('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}', {"canonical": '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}'}),
    ('{"\\ue000":1,"\\ud800\\udc00":2,"a":3,"\\r":4}', {"canonical": '{"\\r":4,"a":3,"𐀀":2,"\ue000":1}'}),
    ('{"b":-0.0,"a":1e-7,"c":1e-6,"d":1e20,"e":1e21}', {"canonical": '{"a":1e-7,"b":0,"c":0.000001,"d":100000000000000000000,"e":1e+21}'}),
    ('{"text":"é/e\\u0301","array":[{"z":1,"a":2}]}', {"canonical": '{"array":[{"a":2,"z":1}],"text":"é/é"}'}),
    ('{"a":1,"a":2}', {"error": "invalid_json"}),
    ('{"nested":{"a":1,"a":2}}', {"error": "invalid_json"}),
    ('{"x":"\\ud800"}', {"error": "invalid_json"}),
    ('{"x":1e999}', {"error": "invalid_json"}),
    ('{"x":9007199254740993}', {"error": "invalid_json"}),
]
write("jcs.json", {"cases": [{"json": raw} for raw, _ in jcs_cases], "expect": [expected for _, expected in jcs_cases]})
number_cases = [
    ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"), ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"),
    ("7ff0000000000000", None), ("7ff8000000000000", None),
]
write("jcs_numbers.json", {"source": "https://www.rfc-editor.org/rfc/rfc8785#appendix-B", "cases": [{"bits": bits} for bits, _ in number_cases],
                           "expect": [{"canonical": text} if text is not None else {"error": "invalid_json"} for _, text in number_cases]})
path_cases = [("/a/b/../c/./", "/a/c/"), ("/%2e%2e/a//b/%7e/%2f", "/a//b/~/%2F"), ("/a/../../../b", "/b"), ("/a/..", "/"), ("/a//b", "/a//b"), ("/a/%zz", None), ("relative", None), ("/a?x=1", None)]
write("path_normalization.json", {"cases": [{"path": path} for path, _ in path_cases], "expect": [{"path": expected} if expected is not None else {"error": "invalid_json"} for _, expected in path_cases]})

validation_cases = []


def dc(name, updates, error=None, request_updates=None, key="quick", record=APPROVER):
    value = copy.deepcopy(DECISION); value.update(updates)
    request = copy.deepcopy(REQUEST); request.update(request_updates or {})
    validation_cases.append({"name": name, "decision": signed(value, KEYS[key]), "request": request, "device": record, "now": NOW,
                             "expect": {"error": error} if error else {"ok": True}})


dc("digest_mismatch", {"digest": "00" * 32}, "digest_mismatch")
dc("nonce_mismatch", {"nonce": b64(bytes(16))}, "nonce_mismatch")
dc("t2_quick", {}, "insufficient_level", {"tier": "T2", "min_level": "strong", "scope_options": ["per_use"]})
dc("strong_signed_with_quick", {"level": "strong"}, "invalid_signature")
dc("identity_cannot_approve", {}, "invalid_signature", key="recipient")
dc("scope_broadening", {"scope": {"mode": "standing", "level": "device", "until": 0}, "level": "strong"}, "invalid_scope", {"scope_options": ["per_use"]}, key="strong")
dc("standing_quick", {"scope": {"mode": "standing", "level": "credential", "until": 0}}, "insufficient_level")
dc("remember_exact_hour", {"scope": {"mode": "remember", "level": "credential", "until": NOW + 3600}})
dc("remember_extra_second", {"scope": {"mode": "remember", "level": "credential", "until": NOW + 3601}}, "invalid_scope")
dc("unknown_authority", {"approver_kind": "future-service"}, "unsupported_authority")
dc("reserved_quorum", {"quorum": {"m": 1, "n": 1, "sigs": []}}, "unsupported_authority")
dc("wrong_approver", {"approver": "dev_other"}, "wrong_sender")
dc("wrong_approval", {"approval_id": "01J9W000000000000000000002"}, "not_waiting")
dc("reason_null_preserved", {"decision": "deny", "reason": None})
dc("quorum_missing_preserved", {})
validation_cases[-1]["decision"].pop("quorum")
validation_cases[-1]["decision"] = signed(validation_cases[-1]["decision"], KEYS["quick"])
dc("unknown_top_and_nested", {"scope": {**DECISION["scope"], "future_scope": {"nested": [1, None]}}})
expired = copy.deepcopy(validation_cases[0]); expired.update(name="expired", now=REQUEST["exp"] + 1); expired["expect"] = {"error": "expired"}; validation_cases.append(expired)
boundary = copy.deepcopy(validation_cases[-2]); boundary.update(name="expiry_equality", now=REQUEST["exp"]); validation_cases.append(boundary)
write("decision_validation_cases.json", {"keys": KEY_DATA, "canonical": canonical_input, "cases": [{k: v for k, v in c.items() if k != "expect"} for c in validation_cases], "expect": [c["expect"] for c in validation_cases]})

grant_cases = []


def gc(name, updates, error=None, level="strong", key="strong", record=APPROVER):
    value = copy.deepcopy(GRANT); value.update(updates)
    grant_cases.append({"name": name, "grant": signed(value, KEYS[key]), "device": record, "level": level, "expect": {"error": error} if error else {"ok": True}})


gc("finite_t2_settings", {"scope": {**GRANT["scope"], "max_tier": "T2"}, "exp": NOW + 604800})
gc("standing_t2_confirm", {"scope": {**GRANT["scope"], "max_tier": "T2"}, "confirm": "srv"})
gc("standing_t2_missing_confirm", {"scope": {**GRANT["scope"], "max_tier": "T2"}}, "invalid_grant")
gc("standing_t2_wrong_confirm", {"scope": {**GRANT["scope"], "max_tier": "T2"}, "confirm": "another"}, "invalid_grant")
gc("global_requires_star", {"scope": {"level": "global", "max_tier": "T1"}}, "invalid_grant")
gc("global_star", {"scope": {"level": "global", "max_tier": "T1"}, "aud": "*"})
gc("wrong_audience", {"aud": "dev_other"}, "wrong_recipient")
gc("standing_quick", {}, "insufficient_level", "quick", "quick")
gc("algorithm_confusion", {"iss_alg": "RS256"}, "unsupported_algorithm")
gc("unknown_issuer", {"iss_kind": "future-org"}, "unsupported_authority")
gc("expired", {"exp": NOW - 1}, "expired")
gc("rs256_grant", {"iss_alg": "RS256"}, key="rsa", record=device("recipient", True, True))
write("grant_validation_cases.json", {"keys": KEY_DATA, "audience": "dev_srv", "audience_label": "srv", "now": NOW, "cases": [{k: v for k, v in c.items() if k != "expect"} for c in grant_cases], "expect": [c["expect"] for c in grant_cases]})

envelope_cases = []
for field, value in [("v", 2), ("type", "directive"), ("id", "01J9W000000000000000000002"), ("account", "acct_other"), ("from", "dev_other"), ("to", "dev_other"), ("created_at", NOW), ("exp", NOW + 400)]:
    changed = copy.deepcopy(ENVELOPE); changed[field] = value
    envelope_cases.append({"name": field, "envelope": changed, "expect": {"hpke_error": "decryption_failed"}})
changed = copy.deepcopy(ENVELOPE); changed["future_header"] = {"flag": True}
envelope_cases.append({"name": "unknown_header", "envelope": changed, "expect": {"hpke_error": "decryption_failed"}})
changed = copy.deepcopy(ENVELOPE); changed["enc"] = b64(point(KEYS["wrong"]))
envelope_cases.append({"name": "enc", "envelope": changed, "expect": {"hpke_error": "decryption_failed"}})
changed = copy.deepcopy(ENVELOPE); data = bytearray(unb64(changed["ct"])); data[0] ^= 1; changed["ct"] = b64(data)
envelope_cases.append({"name": "ct", "envelope": changed, "expect": {"hpke_error": "decryption_failed"}})
write("envelope_tampering.json", {"keys": KEY_DATA, "cases": [{k: v for k, v in c.items() if k != "expect"} for c in envelope_cases], "expect": [c["expect"] for c in envelope_cases]})
write("envelope_rejections.json", {"keys": KEY_DATA, "envelope": ENVELOPE, "sender": SERVER, "now": NOW, "expect": {"unsupported_version": "unsupported_version", "unknown_type": "unsupported_type", "wrong_recipient": "wrong_recipient", "wrong_sender": "wrong_sender", "expired": "expired", "oversize": "payload_too_large", "malformed_point": "invalid_key", "bad_signature": "invalid_signature"}})

negative_schema = []
for name, sample, updates in [("ApprovalRequest", REQUEST, {"tier": "T3"}), ("ApprovalRequest", REQUEST, {"tier": "T2"}), ("Grant", GRANT, {"scope": {"level": "global", "max_tier": "T1"}}), ("Directive", directive("per_use", KEYS["quick"]), {"op": "future_op"}), ("QueryAuditArgs", SAMPLES["QueryAuditArgs"], {"limit": 201}), ("Budget", SAMPLES["Budget"], {"per": "2h"}), ("ToolResult", TOOL, {"result": {"body": "test"}}), ("DeviceRecord", APPROVER, {"ak_q": {"pub": pub(KEYS["quick"]), "alg": "HS256"}})]:
    value = copy.deepcopy(sample); value.update(updates); negative_schema.append({"type": name, "schema": snake(name) + ".schema.json", "value": value})
missing = copy.deepcopy(REQUEST); missing.pop("agent"); negative_schema.append({"type": "ApprovalRequest", "schema": "approval_request.schema.json", "value": missing})
write("schema_rejections.json", {"samples": negative_schema, "expect": [False] * len(negative_schema)})

caller_ops = {"relay_client": OPS[:4] + ["remote.relay.identity", "remote.relay.outbound.ack", "remote.relay.control.poll", "remote.relay.control.complete", "remote.relay.control.sign"], "hook": ["remote.pending.for_agent", "remote.pending.stop_block"], "mcp": ["remote.wait", "remote.pending.list", "remote.status", "remote.client_timeout_observed"],
              "cli_owner": ["remote.account.recover", "remote.audit.list", "remote.pending.list", "remote.decide", "remote.grant.issue", "remote.grant.list", "remote.grant.revoke", "remote.directive.issue", "remote.pair.start", "remote.pair.complete", "remote.pair.confirm", "remote.devices.list", "remote.devices.revoke", "remote.devices.rename", "remote.status"],
              "approval_agent": ["remote.presence.update", "remote.decide", "remote.grant.issue", "remote.directive.issue", "remote.pair.start", "remote.pair.complete", "remote.pair.confirm"]}
write("ipc_contracts.json", {"ops": OPS, "request": {"op": "remote.status", "params": {}, "future": {"flag": True}}, "response": {"ok": False, "error": {"code": "forbidden", "message": "Access denied", "future": None}, "future": True},
                            "expect": {"ops": OPS, "allowed": caller_ops, "request_roundtrip": True, "response_roundtrip": True, "unknown_op_rejected": True, "false_success_rejected": True}})
write("provider_adapter.json", {"keys": KEY_DATA, "envelope": ENVELOPE, "sender": SERVER, "recipient": APPROVER, "now": NOW,
                                "expect": {"sign_ok": True, "open_ok": True, "public_jwk_ok": True, "presence": "unlocked", "key_kind": "tpm2", "error": "key_unavailable"}})
print(f"Generated {len(DEFS)} schemas and public protocol fixtures.")
