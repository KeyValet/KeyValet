use super::{text, Error, Result};
use serde_json::Value;
use std::collections::HashSet;

pub const MAX_WAKE_POPUPS: usize = 5;

#[derive(Clone, Default)]
pub struct WakeQueue {
    shown: usize,
    seen: HashSet<String>,
}
pub struct WakeBatch {
    pub popups: Vec<Value>,
    pub remaining_ids: Vec<String>,
}
impl WakeQueue {
    pub fn wake(&mut self) {
        self.shown = 0;
        self.seen.clear();
    }

    // CONTRACT: §9.2: finishing a dialog does not refill the current wake's automatic budget.
    pub fn enqueue(&mut self, requests: &[Value], now: i64) -> Result<WakeBatch> {
        let mut next = self.clone();
        let mut batch = WakeBatch {
            popups: Vec::new(),
            remaining_ids: Vec::new(),
        };
        let mut batch_seen = HashSet::new();
        for request in requests {
            let id = text(request, "approval_id")?.to_owned();
            let exp = request["exp"].as_i64().ok_or(Error::InvalidRequest)?;
            if exp < now || next.seen.contains(&id) || !batch_seen.insert(id.clone()) {
                continue;
            }
            match text(&request["delivery"], "mode")? {
                "banner" if next.shown < MAX_WAKE_POPUPS => {
                    next.seen.insert(id);
                    next.shown += 1;
                    batch.popups.push(request.clone());
                }
                "banner" => {
                    next.seen.insert(id.clone());
                    batch.remaining_ids.push(id);
                }
                "silent" => batch.remaining_ids.push(id),
                _ => return Err(Error::InvalidRequest),
            }
        }
        *self = next;
        Ok(batch)
    }
}

#[derive(Default)]
pub struct DesktopAdmission {
    wake: WakeQueue,
}
impl DesktopAdmission {
    pub fn admit(&mut self, input: &Value, now: i64) -> Result<bool> {
        if input["op"] == "remote_wake" {
            self.wake.wake();
            return Ok(false);
        }
        if input["op"] != "remote_approval" {
            return Ok(true);
        }
        let mut context = super::DisplayContext::from_json(&input["context"])?;
        context.now = now;
        super::ApprovalView::new(&input["request"], context, super::Platform::Macos)?;
        match text(&input["request"]["delivery"], "mode")? {
            "silent" => return Ok(false),
            "banner" => (),
            _ => return Err(Error::InvalidRequest),
        }
        if context.backlog_count == 0 {
            return Ok(true);
        }
        Ok(!self
            .wake
            .enqueue(std::slice::from_ref(&input["request"]), now)?
            .popups
            .is_empty())
    }
}
