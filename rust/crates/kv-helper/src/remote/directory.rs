//! Directory publication follows the same durable commit decision as SQLite.
use super::engine::{directory, random_nonce, State};
use super::{DeviceMirror, RemoteHelper, Result};
use kv_core::remote::DeviceRecord;

pub(crate) fn same_authority(a: &DeviceRecord, b: &DeviceRecord) -> bool {
    kv_core::remote::validation::same_device_authority(a, b)
}

pub(crate) struct Update<'a> {
    mirror: &'a dyn DeviceMirror,
    id: String,
    committed: bool,
    changed: bool,
}

impl Update<'_> {
    pub fn commit(mut self) -> Result<()> {
        // Once SQLite commits, publication must remain recoverable even if the vault is offline.
        self.committed = true;
        if self.changed {
            self.mirror.commit(&self.id)
        } else {
            Ok(())
        }
    }
}

impl Drop for Update<'_> {
    fn drop(&mut self) {
        if !self.committed && self.changed {
            let _ = self.mirror.abort(&self.id);
        }
    }
}

impl RemoteHelper {
    pub(crate) fn stage_directory<'a>(&'a self, state: &State) -> Result<Update<'a>> {
        let id = random_nonce()?;
        let mut update = Update {
            mirror: &*self.services.mirror,
            id,
            committed: false,
            changed: false,
        };
        if update
            .mirror
            .prepare(&self.account, &directory(&state.store)?, &update.id)?
        {
            update.changed = true;
            state
                .store
                .db
                .execute("INSERT INTO directory_commits(id) VALUES(?1)", [&update.id])?;
        }
        Ok(update)
    }

    pub(crate) fn rename_device_rows(&self, state: &State, id: &str, label: &str) -> Result<()> {
        if label.trim().is_empty() || label.len() > 100 || label.chars().any(char::is_control) {
            return Err(super::Error("invalid_device_label"));
        }
        let mut record = state.store.device(id, &self.account)?;
        record.label = label.into();
        state.store.db.execute(
            "UPDATE devices SET label=?1,record_json=?2 WHERE id=?3",
            rusqlite::params![label, super::store::encode(&record)?, id],
        )?;
        if id == self.local.device_id {
            state
                .store
                .set_setting("device_label", &label, "local", self.services.clock.now())?;
        }
        Ok(())
    }
}
