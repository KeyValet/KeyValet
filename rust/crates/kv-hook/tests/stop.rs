use kv_hook::stop::{handle_stop, MAX_BLOCKS};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

const ID: &str = "01J00000000000000000000000";

#[test]
fn five_runtime_schemas_match_the_snapshot_and_share_a_three_block_limit() {
    let expected: Value = serde_json::from_str(include_str!("snapshots/stop.json")).unwrap();
    for mode in [
        "stop",
        "devin-stop",
        "codex-stop",
        "cursor-stop",
        "gemini-after-agent",
    ] {
        let blocks = AtomicU64::new(0);
        for attempt in 0..=MAX_BLOCKS {
            let output = handle_stop(
                mode,
                &json!({"session_id": "untrusted-session-name"}),
                4242,
                100,
                |op, params| match op {
                    "remote.pending.for_agent" => {
                        assert_eq!(params, json!({"agent_pid": 4242}));
                        Ok(
                            json!({"pending": [{"approval_id": ID, "expires_at": 101, "stop_hook_blocks": blocks.load(Ordering::SeqCst)}]}),
                        )
                    }
                    "remote.pending.stop_block" => {
                        assert_eq!(params, json!({"approval_id": ID}));
                        let count = blocks.fetch_add(1, Ordering::SeqCst);
                        Ok(
                            json!({"allowed": count < MAX_BLOCKS, "blocks_left": MAX_BLOCKS.saturating_sub(count + 1)}),
                        )
                    }
                    _ => panic!("Unexpected helper operation"),
                },
            );
            assert!(output.had_pending);
            if attempt < MAX_BLOCKS {
                assert_eq!(output.value, expected[mode]);
            } else {
                assert_eq!(output.value, json!({}));
            }
        }
        assert_eq!(blocks.load(Ordering::SeqCst), 3);
    }
}

#[test]
fn empty_expired_consumed_and_loop_guards_have_no_counter_side_effects() {
    for pending in [
        json!([]),
        json!([{"approval_id": ID, "expires_at": 99, "stop_hook_blocks": 0}]),
        json!([{"approval_id": ID, "expires_at": 101, "stop_hook_blocks": 3}]),
    ] {
        let mut queries = 0;
        let result = handle_stop("stop", &json!({}), 4242, 100, |op, _| {
            assert_eq!(op, "remote.pending.for_agent");
            queries += 1;
            Ok(json!({"pending": pending}))
        });
        assert_eq!(result.value, json!({}));
        assert_eq!(queries, 1);
        assert_eq!(result.had_pending, !pending.as_array().unwrap().is_empty());
    }
    for input in [
        json!({"stop_hook_active": true}),
        json!({"stopHookActive": true}),
        json!({"loop_count": 3}),
        json!({"loopCount": 4}),
    ] {
        let result = handle_stop("cursor-stop", &input, 4242, 100, |_, _| {
            panic!("Loop guards must not query or mutate helper state")
        });
        assert_eq!(result.value, json!({}));
    }
}

#[test]
fn concurrent_pending_ids_are_listed_once_and_helper_remains_authoritative() {
    let other = "01J00000000000000000000001";
    let result = handle_stop("stop", &json!({}), 4242, 100, |op, params| {
        if op == "remote.pending.for_agent" {
            Ok(json!({"pending": [
                {"approval_id": ID, "expires_at": 101, "stop_hook_blocks": 0},
                {"approval_id": ID, "expires_at": 101, "stop_hook_blocks": 0},
                {"approval_id": other, "expires_at": 101, "stop_hook_blocks": 0},
                {"approval_id": "invalid\nheader", "expires_at": 101, "stop_hook_blocks": 0}
            ]}))
        } else {
            Ok(json!({"allowed": params["approval_id"] != other, "blocks_left": 0}))
        }
    });
    let reason = result.value["reason"].as_str().unwrap();
    assert_eq!(reason.matches(ID).count(), 1);
    assert!(!reason.contains(other));
}

#[test]
fn malformed_queries_and_entries_allow_without_mutating_pending_state() {
    for mode in ["unknown-mode", "gemini-stop", "claude-stop"] {
        let result = handle_stop(mode, &json!({}), 4242, 100, |_, _| {
            Err(std::io::Error::other("Synthetic disconnect"))
        });
        assert_eq!(result.value, json!({}));
        assert!(!result.had_pending);
    }
    for response in [
        json!({}),
        json!({"pending": null}),
        json!({"pending": [ {},
        {"approval_id": ID, "expires_at": 101},
        {"approval_id": ID, "expires_at": 100, "stop_hook_blocks": 0} ]}),
    ] {
        let result = handle_stop("stop", &json!({}), 4242, 100, |op, _| {
            assert_eq!(op, "remote.pending.for_agent");
            Ok(response.clone())
        });
        assert_eq!(result.value, json!({}));
    }
}
