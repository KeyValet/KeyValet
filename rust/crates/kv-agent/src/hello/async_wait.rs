//! Completion policy shared by WinRT operations and deterministic OS fakes.
use std::time::{Duration, Instant};

pub(super) fn wait<E>(
    timeout: Duration,
    subscribe: impl FnOnce() -> Result<(), E>,
    mut completed: impl FnMut() -> bool,
    mut started: impl FnMut() -> Result<bool, E>,
    mut cancel: impl FnMut() -> Result<(), E>,
    timeout_error: impl FnOnce() -> E,
) -> Result<(), E> {
    // Subscription time consumes the same cap; an operation never gets a fresh timeout.
    let deadline = Instant::now() + timeout;
    if let Err(error) = subscribe() {
        let _ = cancel();
        return Err(error);
    }
    loop {
        if Instant::now() >= deadline {
            let _ = cancel();
            return Err(timeout_error());
        }
        // The completion delegate is authoritative even when a remote producer's
        // status snapshot still says Started. Callers must still validate GetResults.
        if completed() || !started()? {
            return Ok(());
        }
        std::thread::sleep(
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

pub(super) fn terminal_status(status: i32) -> bool {
    // Windows.Foundation.AsyncStatus: Completed, Canceled, Error. Unknown values
    // cannot release a caller waiting for an authenticated operation result.
    matches!(status, 1..=3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn completion_callback_wins_over_stale_started_status() {
        let completed = Cell::new(false);
        assert_eq!(
            wait(
                Duration::from_millis(10),
                || {
                    completed.set(true);
                    Ok(())
                },
                || completed.get(),
                || Ok(true),
                || Ok(()),
                || "timeout",
            ),
            Ok(())
        );
        assert!(completed.get());
    }

    #[test]
    fn completion_after_the_original_deadline_is_denied() {
        let completed = Cell::new(false);
        let cancelled = Cell::new(false);
        assert_eq!(
            wait(
                Duration::from_millis(1),
                || {
                    std::thread::sleep(Duration::from_millis(2));
                    completed.set(true);
                    Ok(())
                },
                || completed.get(),
                || Ok(false),
                || {
                    cancelled.set(true);
                    Ok(())
                },
                || "expired",
            ),
            Err("expired")
        );
        assert!(cancelled.get());
    }

    #[test]
    fn only_known_terminal_callback_statuses_can_release_a_waiter() {
        for status in [1, 2, 3] {
            assert!(terminal_status(status));
        }
        for status in [0, -1, 4, i32::MAX] {
            assert!(!terminal_status(status));
        }
    }

    #[test]
    fn completion_subscription_is_registered_before_polling() {
        // A producer publishes its terminal state only once the client subscribes. Polling
        // alone reproduces the Hello cancellation timeout without calling a real OS API.
        let subscribed = Cell::new(false);
        let cancelled = Cell::new(false);
        assert_eq!(
            wait(
                Duration::from_millis(10),
                || {
                    subscribed.set(true);
                    Ok(())
                },
                || false,
                || Ok(!subscribed.get()),
                || {
                    cancelled.set(true);
                    Ok(())
                },
                || "timeout",
            ),
            Ok(())
        );
        assert!(subscribed.get());
        assert!(!cancelled.get());
    }

    #[test]
    fn registration_failure_is_denied_and_cancelled() {
        let cancelled = Cell::new(false);
        assert_eq!(
            wait(
                Duration::from_secs(1),
                || Err("registration denied"),
                || false,
                || panic!("failed subscription must not poll or consume a result"),
                || {
                    cancelled.set(true);
                    Err("cancel failed")
                },
                || "timeout",
            ),
            Err("registration denied")
        );
        assert!(cancelled.get());
    }

    #[test]
    fn status_query_failure_does_not_become_success() {
        assert_eq!(
            wait(
                Duration::from_secs(1),
                || Ok(()),
                || false,
                || Err("status denied"),
                || Ok(()),
                || "timeout",
            ),
            Err("status denied")
        );
    }

    #[test]
    fn stalled_operations_are_denied_even_if_cancellation_fails() {
        let cancelled = Cell::new(false);
        assert_eq!(
            wait(
                Duration::ZERO,
                || Ok(()),
                || false,
                || Ok(true),
                || {
                    cancelled.set(true);
                    Err("cancel failed")
                },
                || "timeout",
            ),
            Err("timeout")
        );
        assert!(cancelled.get());
    }

    #[test]
    fn subscription_time_consumes_the_original_cap() {
        let cancelled = Cell::new(false);
        let polls = Cell::new(0);
        assert_eq!(
            wait(
                Duration::from_millis(1),
                || {
                    std::thread::sleep(Duration::from_millis(2));
                    Ok(())
                },
                || false,
                || {
                    polls.set(polls.get() + 1);
                    Ok(polls.get() == 1)
                },
                || {
                    cancelled.set(true);
                    Ok(())
                },
                || "expired",
            ),
            Err("expired")
        );
        assert!(cancelled.get());
    }
}
