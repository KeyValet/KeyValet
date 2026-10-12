PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    recovery_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'self_hosted'
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    dk_pub TEXT NOT NULL UNIQUE,
    akq_pub TEXT, akq_alg TEXT, aks_pub TEXT, aks_alg TEXT,
    key_kind TEXT NOT NULL, attestation BLOB, os TEXT NOT NULL,
    caps TEXT NOT NULL, label TEXT NOT NULL,
    created_at INTEGER NOT NULL, revoked_at INTEGER, last_seen INTEGER,
    record BLOB NOT NULL, push_token BLOB
);
CREATE INDEX IF NOT EXISTS devices_account ON devices(account_id);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    exp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id);
CREATE TABLE IF NOT EXISTS pairings (
    pairing_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    initiator_device TEXT NOT NULL REFERENCES devices(id),
    initiator_pubs BLOB NOT NULL, joiner_pubs BLOB,
    joiner_device TEXT REFERENCES devices(id),
    state TEXT NOT NULL CHECK(state IN ('offered', 'accepted', 'finished', 'expired')),
    exp INTEGER NOT NULL, initiator_finished INTEGER NOT NULL DEFAULT 0,
    joiner_finished INTEGER NOT NULL DEFAULT 0, sas_hash TEXT
);
CREATE INDEX IF NOT EXISTS pairings_joiner ON pairings(joiner_device, state);
CREATE TABLE IF NOT EXISTS used_pair_tokens (
    token_hash TEXT PRIMARY KEY, exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
    requester TEXT NOT NULL REFERENCES devices(id),
    state TEXT NOT NULL CHECK(state IN ('waiting', 'resolved', 'cancelled', 'expired')),
    exp INTEGER NOT NULL, resolved_by TEXT REFERENCES devices(id), resolved_at INTEGER,
    PRIMARY KEY(account_id, id)
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
    from_device TEXT NOT NULL REFERENCES devices(id),
    to_device TEXT NOT NULL REFERENCES devices(id), type TEXT NOT NULL,
    envelope BLOB NOT NULL, created_at INTEGER NOT NULL, exp INTEGER NOT NULL,
    delivered_at INTEGER, acked_at INTEGER,
    PRIMARY KEY(account_id, id, to_device, type)
);
CREATE INDEX IF NOT EXISTS messages_inbox ON messages(to_device, acked_at, exp);
CREATE INDEX IF NOT EXISTS approvals_waiting ON approvals(account_id, state, exp);

CREATE TABLE IF NOT EXISTS push_jobs (
    account_id TEXT NOT NULL, id TEXT NOT NULL, to_device TEXT NOT NULL,
    type TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('silent','banner')),
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(account_id,id,to_device,type),
    FOREIGN KEY(account_id,id,to_device,type)
        REFERENCES messages(account_id,id,to_device,type) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS push_jobs_due ON push_jobs(next_attempt,expires_at);

CREATE TABLE IF NOT EXISTS login_users (
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL,
    email TEXT NOT NULL, display_name TEXT NOT NULL, created_at INTEGER NOT NULL,
    UNIQUE(provider,subject)
);
CREATE TABLE IF NOT EXISTS device_users (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    user_id TEXT NOT NULL REFERENCES login_users(id)
);
CREATE TABLE IF NOT EXISTS account_owners (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES login_users(id)
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, nonce_hash TEXT NOT NULL,
    state TEXT NOT NULL UNIQUE, device BLOB NOT NULL, exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS account_sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES login_users(id),
    device_id TEXT NOT NULL REFERENCES devices(id), exp INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS device_session_users (
    token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
    account_session TEXT NOT NULL REFERENCES account_sessions(token_hash) ON DELETE CASCADE
);

PRAGMA user_version = 3;
