use std::time::Duration;

pub struct Backoff {
    initial: Duration,
    next: Duration,
    maximum: Duration,
}

impl Backoff {
    pub fn new(initial: Duration, maximum: Duration) -> Self {
        Self {
            initial,
            next: initial,
            maximum,
        }
    }

    pub fn reset(&mut self) {
        self.next = self.initial;
    }

    pub fn delay(&mut self, retry_after: Option<Duration>) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.maximum);
        // An explicit server cooldown takes precedence over the reconnect ceiling.
        delay.max(retry_after.unwrap_or_default())
    }
}
