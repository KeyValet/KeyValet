-- Appendix D columns remain stable; lossless signed objects use explicit extension columns.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL, label TEXT NOT NULL, os TEXT NOT NULL, key_kind TEXT NOT NULL,
  dk_pub TEXT NOT NULL, akq_pub TEXT, akq_alg TEXT, aks_pub TEXT, aks_alg TEXT,
  caps TEXT NOT NULL, attestation BLOB, trust TEXT NOT NULL, added_at INTEGER NOT NULL, revoked_at INTEGER,
  record_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS directory_commits (id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS device_revocations (device_id TEXT PRIMARY KEY,body_json TEXT NOT NULL,relay_done INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS device_revocation_targets (device_id TEXT NOT NULL,peer TEXT NOT NULL,envelope_json TEXT NOT NULL,
  PRIMARY KEY(device_id,peer));
CREATE TABLE IF NOT EXISTS pending_approvals (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL, nonce TEXT NOT NULL, canonical_json TEXT NOT NULL,
  exp INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, resolved_at INTEGER,
  approver TEXT, level TEXT, scope_json TEXT, agent_pid INTEGER, agent_runtime TEXT,
  stop_hook_blocks INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, escalated_at INTEGER,
  request_json TEXT NOT NULL, decision_json TEXT, session_id TEXT NOT NULL, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, digest TEXT NOT NULL, used_at INTEGER NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grants (
  jti TEXT PRIMARY KEY, iss TEXT NOT NULL, iss_alg TEXT NOT NULL, aud TEXT NOT NULL, level TEXT NOT NULL, credential TEXT,
  hosts_json TEXT, methods_json TEXT, paths_json TEXT, agent TEXT, max_tier TEXT NOT NULL,
  budget_json TEXT, budget_left_json TEXT, nbf INTEGER, exp INTEGER, origin TEXT NOT NULL, sig TEXT NOT NULL,
  installed_at INTEGER NOT NULL, revoked_at INTEGER, object_json TEXT NOT NULL, authority_json TEXT NOT NULL,
  session_id TEXT);
CREATE TABLE IF NOT EXISTS directives (id TEXT PRIMARY KEY, iss TEXT NOT NULL, op TEXT NOT NULL, args_json TEXT NOT NULL,
  applied_at INTEGER NOT NULL, ok INTEGER NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, set_by TEXT NOT NULL, set_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS revoked_jti (jti TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS issued_approvals (approval_id TEXT PRIMARY KEY, peer TEXT NOT NULL, kind TEXT NOT NULL, digest TEXT NOT NULL,
  decision TEXT NOT NULL, level TEXT NOT NULL, scope_json TEXT, issued_at INTEGER NOT NULL, summary_text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approval_history (seq INTEGER PRIMARY KEY AUTOINCREMENT,
  approval_id TEXT NOT NULL UNIQUE REFERENCES issued_approvals(approval_id));
CREATE TABLE IF NOT EXISTS issued_grants (jti TEXT PRIMARY KEY, peer TEXT NOT NULL, level TEXT NOT NULL, credential TEXT, max_tier TEXT NOT NULL,
  exp INTEGER, origin TEXT NOT NULL, issued_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS issued_directives (id TEXT PRIMARY KEY, peer TEXT NOT NULL, op TEXT NOT NULL, issued_at INTEGER NOT NULL,
  result_ok INTEGER, result_summary TEXT);
CREATE TABLE IF NOT EXISTS issued_grant_objects (jti TEXT PRIMARY KEY REFERENCES issued_grants(jti), object_json TEXT NOT NULL,
  issued_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS issued_grant_usage (jti TEXT NOT NULL REFERENCES issued_grants(jti), peer TEXT NOT NULL,
  usage_json TEXT NOT NULL, fetched_at INTEGER NOT NULL, PRIMARY KEY(jti,peer));
CREATE TABLE IF NOT EXISTS issued_grant_revocations (jti TEXT PRIMARY KEY REFERENCES issued_grants(jti),
  requested_at INTEGER NOT NULL, confirmed_at INTEGER);
CREATE TABLE IF NOT EXISTS issued_grant_revocation_targets (jti TEXT NOT NULL REFERENCES issued_grant_revocations(jti),
  peer TEXT NOT NULL, confirmed_at INTEGER, PRIMARY KEY(jti,peer));
CREATE TABLE IF NOT EXISTS issued_directive_objects (id TEXT PRIMARY KEY REFERENCES issued_directives(id), object_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grant_use_stats (jti TEXT PRIMARY KEY REFERENCES grants(jti), uses_n INTEGER NOT NULL, last_used_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS peer_state_cache (peer TEXT PRIMARY KEY, mode TEXT, unattended INTEGER, grants_count INTEGER, pending_count INTEGER,
  presence TEXT, last_seen INTEGER, fetched_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, envelope_json TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_outbox_receipts (
  envelope_hash TEXT PRIMARY KEY, stage TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, entry_json TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS pending_agent ON pending_approvals(agent_pid, state, exp);
CREATE INDEX IF NOT EXISTS grants_issuer ON grants(iss, revoked_at);
