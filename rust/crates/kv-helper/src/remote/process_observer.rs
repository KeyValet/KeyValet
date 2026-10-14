//! Runtime identity inspection must retain the authenticated caller's process proof.
use super::production::ProcessIdentity;
use super::{Error, Result};

pub(super) fn observe(
    pid: u32,
    direct: impl FnOnce(u32) -> Result<ProcessIdentity>,
    verified: impl FnOnce(u32) -> Result<ProcessIdentity>,
) -> Result<ProcessIdentity> {
    // A broker result is mandatory. A locally readable process is not a substitute
    // for the live, authenticated socket that authorizes the broker's inspection.
    let proved = verified(pid)?;
    if pid == 0
        || proved.pid != pid
        || proved.start_time == 0
        || proved.exe_sha256.len() != 64
        || !proved
            .exe_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error("agent_identity_mismatch"));
    }
    if let Ok(local) = direct(pid) {
        if local != proved {
            return Err(Error("agent_identity_mismatch"));
        }
    }
    Ok(proved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::production::Processes;
    use crate::remote::Error;

    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            uid: 1000,
            pid: 4242,
            start_time: 1234,
            exe_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn r3a_authenticated_broker_proof_survives_unprivileged_proc_denial() {
        struct Inspector;
        impl Processes for Inspector {
            fn inspect(&self, pid: u32) -> Result<ProcessIdentity> {
                observe(
                    pid,
                    |_| Err(Error("agent_unavailable")),
                    |actual| {
                        assert_eq!(actual, 4242);
                        Ok(identity())
                    },
                )
            }
        }
        let inspector = Inspector;
        let actual = inspector.inspect(4242).unwrap();
        assert!(actual == identity());
    }

    #[test]
    fn broker_failure_or_process_changes_never_fall_back_to_local_claims() {
        assert!(observe(
            4242,
            |_| Ok(identity()),
            |_| Err(Error("agent_unavailable"))
        )
        .is_err());
        for changed in [
            ProcessIdentity {
                uid: 2000,
                ..identity()
            },
            ProcessIdentity {
                pid: 4243,
                ..identity()
            },
            ProcessIdentity {
                start_time: 0,
                ..identity()
            },
            ProcessIdentity {
                exe_sha256: "invalid".into(),
                ..identity()
            },
        ] {
            assert!(observe(4242, |_| Ok(identity()), |_| Ok(changed)).is_err());
        }
    }
}
