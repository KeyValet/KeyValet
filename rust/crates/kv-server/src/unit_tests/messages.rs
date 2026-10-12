use super::*;
use crate::tests::fixture;
use kv_core::remote::relay::ErrorCode;

#[test]
fn corrupted_queries_and_insert_failures_are_sanitized() {
    let fixture = fixture();
    fixture.state.with(|data, now| {
        data.db.execute_batch("CREATE TRIGGER fail_insert BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT,'PRIVATE-DATABASE-ERROR'); END;")?;
        let error = insert(&data.db, &fixture.envelope, fixture.state.now()).unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(!format!("{error:?}").contains("PRIVATE"));
        data.db.execute_batch("DROP TRIGGER fail_insert; DROP TABLE messages;")?;
        assert_eq!(insert(&data.db, &fixture.envelope, fixture.state.now()).unwrap_err().code, ErrorCode::Conflict);
        assert_eq!(pending(&data.db, &fixture.principal.account, now).unwrap_err().code, ErrorCode::Conflict);
        Ok(())
    }).unwrap();
}

#[test]
fn account_capacity_blocks_an_additional_message() {
    let fixture = fixture();
    fixture.state.with(|data, now| {
        for index in 0..MAX_PENDING {
            data.db.execute("INSERT INTO approvals(id,account_id,requester,state,exp) VALUES(?1,?2,?3,'waiting',?4)",
                params![format!("test-{index}"),fixture.principal.account,fixture.principal.device.device_id,now+300])?;
        }
        assert_eq!(send_messages(data, &fixture.principal, std::slice::from_ref(&fixture.envelope), now).unwrap_err().code, ErrorCode::RateLimited);
        Ok(())
    }).unwrap();
}

#[test]
fn an_identical_retry_at_capacity_preserves_the_original_row() {
    let fixture = fixture();
    fixture.state.with(|data, now| {
        for index in 0..MAX_PENDING-1 {
            data.db.execute("INSERT INTO approvals(id,account_id,requester,state,exp) VALUES(?1,?2,?3,'waiting',?4)",
                params![format!("test-{index}"),fixture.principal.account,fixture.principal.device.device_id,now+300])?;
        }
        for _ in 0..2 {
            send_messages(data,&fixture.principal,std::slice::from_ref(&fixture.envelope),now)?;
        }
        assert_eq!(pending(&data.db,&fixture.principal.account,now)?,MAX_PENDING);
        assert_eq!(data.db.query_row("SELECT COUNT(*) FROM messages",[],|row|row.get::<_,i64>(0))?,1);
        Ok(())
    }).unwrap();
}

#[test]
fn duplicate_keys_require_identical_complete_signed_envelopes() {
    let fixture = fixture();
    fixture
        .state
        .with(|data, _| {
            assert!(insert(&data.db, &fixture.envelope, fixture.state.now())?);
            assert!(!insert(&data.db, &fixture.envelope, fixture.state.now())?);
            let mut changed = fixture.envelope.clone();
            changed.extra.insert("different".into(), json!(true));
            assert_eq!(
                insert(&data.db, &changed, fixture.state.now())
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
            assert_eq!(
                data.db
                    .query_row("SELECT COUNT(*) FROM messages", [], |row| row
                        .get::<_, i64>(0))?,
                1
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn readiness_and_delivery_errors_are_sanitized() {
    let fixture = fixture();
    fixture
        .state
        .with(|data, now| {
            data.db.execute_batch("DROP TABLE pairings;")?;
            assert_eq!(
                device_ready(&data.db, &fixture.envelope.to)
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
            assert_eq!(
                data.db
                    .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?,
                0
            );
            data.db.execute_batch("DROP TABLE messages")?;
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            data.presence.insert(
                fixture.envelope.to.clone(),
                crate::state::Presence {
                    connection: "delivery".into(),
                    sender,
                },
            );
            data.deliver(&fixture.envelope, now);
            Ok(())
        })
        .unwrap();
}
