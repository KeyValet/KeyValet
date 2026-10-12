use crate::error::Result;
use crate::messages::cancel_frames;
use crate::state::{query_rows, State, RETENTION};
use rusqlite::params;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    pub messages: usize,
    pub approvals: usize,
    pub expired_approvals: usize,
    pub sessions: usize,
    pub pairings: usize,
}

pub(crate) fn cleanup(state: &State) -> Result<CleanupStats> {
    state.with(|data, now| {
        let tx = data.db.transaction()?;
        crate::push::cleanup_tokens(&tx, now, data.account_login_required)?;
        let expired = query_rows(&tx, "SELECT account_id,id FROM approvals WHERE state='waiting' AND exp<?1",
            params![now], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut notifications = Vec::new();
        for (account, id) in &expired { notifications.extend(cancel_frames(&tx, account, id, None)?); }
        let expired_approvals = tx.execute("UPDATE approvals SET state='expired',resolved_at=?1 WHERE state='waiting' AND exp<?1", [now])?;
        let abandoned = query_rows(&tx, "SELECT joiner_device FROM pairings WHERE state='accepted' AND exp<?1",
            params![now], |row| row.get::<_, String>(0))?;
        for device in &abandoned {
            tx.execute("UPDATE devices SET revoked_at=?1 WHERE id=?2", params![now, device])?;
            tx.execute("DELETE FROM sessions WHERE device_id=?1", [device])?;
        }
        tx.execute("UPDATE pairings SET state='expired',token_hash=NULL WHERE state IN ('offered','accepted') AND exp<?1", [now])?;
        tx.execute("DELETE FROM push_jobs WHERE expires_at<?1", [now])?;
        let mut messages = tx.execute("DELETE FROM messages WHERE acked_at IS NOT NULL AND acked_at<?1
            AND type NOT IN ('approval_request','approval_escalate')", [now - RETENTION])?;
        messages += tx.execute("DELETE FROM messages WHERE type IN ('approval_request','approval_escalate','approval_decision','approval_cancel')
            AND EXISTS(SELECT 1 FROM approvals a WHERE a.account_id=messages.account_id AND a.id=messages.id AND a.exp<?1)", [now - RETENTION])?;
        let approvals = tx.execute("DELETE FROM approvals WHERE exp<?1", [now - RETENTION])?;
        let sessions = tx.execute("DELETE FROM sessions WHERE exp<?1", [now])?;
        tx.execute("DELETE FROM login_attempts WHERE exp<?1", [now])?;
        tx.execute("DELETE FROM account_sessions WHERE exp<?1", [now])?;
        let pairings = tx.execute("DELETE FROM pairings WHERE exp<?1 AND state IN ('finished','expired')", [now - RETENTION])?;
        tx.execute("DELETE FROM used_pair_tokens WHERE exp<?1", [now - RETENTION])?;
        tx.commit()?;
        data.challenges.retain(|_, challenge| challenge.exp >= now);
        for device in abandoned { data.invalidate_device(&device); }
        for (device, frame) in notifications { data.send(&device, frame); }
        Ok(CleanupStats { messages, approvals, expired_approvals, sessions, pairings })
    })
}
