use super::wait_for_shutdown;
use std::future::{pending, ready};

#[tokio::test]
async fn terminate_interrupt_and_signal_registration_failure_all_finish() {
    wait_for_shutdown(Ok(Box::pin(ready(()))), Box::pin(pending())).await;
    wait_for_shutdown(Ok(Box::pin(pending())), Box::pin(ready(Ok(())))).await;
    wait_for_shutdown(
        Err(std::io::Error::other("signal unavailable")),
        Box::pin(ready(Err(std::io::Error::other("interrupt unavailable")))),
    )
    .await;
}
