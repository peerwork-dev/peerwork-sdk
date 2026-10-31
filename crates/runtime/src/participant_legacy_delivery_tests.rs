use super::*;
use crate::{communication_host::write_private, secure_state::create_private_state_directory};

fn setup(
    kind: &str,
    n: usize,
) -> (
    crate::test_support::ProtectedTestDir,
    LegacyDeliverySelection,
) {
    let root = crate::test_support::protected_test_dir();
    let source = root.path().join("old");
    create_private_state_directory(&source).unwrap();
    let idpath = root.path().join("identity");
    let identity = KernelIdentity::create(&idpath).unwrap();
    let binding = "a".repeat(64);
    let db = database(&source, "receiver.sqlite").unwrap();
    db.execute_batch("CREATE TABLE control(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE deliveries(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL,status TEXT NOT NULL,receipt TEXT,body_hash TEXT);").unwrap();
    db.execute(
        "INSERT INTO control VALUES('binding',?1)",
        [serde_json::to_string(&binding).unwrap()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO control VALUES('selftest',?1)",
        [r#"{ "status": "UNCERTAIN", "message_id": "old-probe" }"#],
    )
    .unwrap();
    let tx = db.unchecked_transaction().unwrap();
    for sequence in 0..n {
        tx.execute(
            "INSERT INTO deliveries VALUES(?1,?2,?3,?4,?5)",
            params![
                sequence,
                format!(r#"{{ "sequence": {sequence}, "text": "PRIVATE-ORIGINAL-BODY" }}"#),
                if sequence % 2 == 0 {
                    "UNCERTAIN"
                } else {
                    "ACKED"
                },
                if sequence % 2 == 0 {
                    None
                } else {
                    Some("old-host-receipt")
                },
                "b".repeat(64)
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    if kind == "BRIDGE" {
        write_private(&source.join("deliveries.json"),br#"[ { "key":"opaque-original-key", "digest":"original-digest", "wire_digest":"original-wire", "status":"UNKNOWN" }, {"key":"acked-key","status":"DONE","receipt":{"state":"HOST_QUEUED","receipt":"original-receipt"}} ]"#).unwrap();
    }
    let selection = LegacyDeliverySelection {
        format: "peerwork.legacy-delivery-import.v1".into(),
        source_directory: source,
        archive_directory: root.path().join("archive"),
        identity_path: idpath,
        expected_actor: identity.actor_id().into(),
        expected_binding_digest: binding,
        kind: kind.into(),
        source_stopped: true,
    };
    (root, selection)
}
fn finish(s: &LegacyDeliverySelection) -> Value {
    import_all(s).unwrap()
}
#[test]
fn bounded_pages_keep_exact_unknown_acked_and_control_evidence_without_native_replay() {
    let (_root, s) = setup("RECEIVER", 65);
    let first = import_page(&s).unwrap();
    assert_eq!(first["archived_records"], 2);
    let second = import_page(&s).unwrap();
    assert_eq!(second["archived_records"], 34);
    let third = import_page(&s).unwrap();
    assert_eq!(third["archived_records"], 66);
    let end = finish(&s);
    assert_eq!(end["archived_records"], 67);
    assert_eq!(import_page(&s).unwrap(), end);
    let unknown = read_evidence(&s, "delivery:0").unwrap();
    assert_eq!(unknown["evidence"]["original_status"], "UNCERTAIN");
    assert_eq!(
        unknown["evidence"]["original_event_json"],
        r#"{ "sequence": 0, "text": "PRIVATE-ORIGINAL-BODY" }"#
    );
    assert_eq!(unknown["native_delivery"], "NOT_CREATED");
    let acked = read_evidence(&s, "delivery:1").unwrap();
    assert_eq!(acked["evidence"]["original_status"], "ACKED");
    assert_eq!(acked["evidence"]["original_receipt"], "old-host-receipt");
    assert_eq!(acked["model_response"], "NOT_ATTESTED");
    assert_eq!(
        read_evidence(&s, "control:selftest").unwrap()["evidence"]["original_json"],
        r#"{ "status": "UNCERTAIN", "message_id": "old-probe" }"#
    );
    let db = source(&s).unwrap();
    let binding: String = db
        .query_row("SELECT value FROM control WHERE key='binding'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(
        binding,
        serde_json::to_string(&s.expected_binding_digest).unwrap()
    );
    let count: usize = db
        .query_row("SELECT count(*) FROM deliveries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 65);
    assert!(!s.archive_directory.join("participant.sqlite").exists());
    assert!(!s.archive_directory.join("inbox.sqlite").exists());
    let raw = std::fs::read(s.archive_directory.join("legacy-delivery.sqlite")).unwrap();
    assert!(!raw
        .windows(b"PRIVATE-ORIGINAL-BODY".len())
        .any(|w| w == b"PRIVATE-ORIGINAL-BODY"));
}
#[test]
fn stopped_assertion_lock_identity_and_source_binding_fail_closed() {
    let (_root, s) = setup("RECEIVER", 1);
    let mut wrong = s.clone();
    wrong.source_stopped = false;
    assert_eq!(
        import_page(&wrong).unwrap_err().code,
        "LEGACY_DELIVERY_SELECTION_INVALID"
    );
    write_private(&s.source_directory.join("receiver.lock"), br#"{"pid":1}"#).unwrap();
    assert_eq!(
        import_page(&s).unwrap_err().code,
        "LEGACY_DELIVERY_SOURCE_STILL_LOCKED"
    );
    assert!(!s.archive_directory.exists());
    std::fs::remove_file(s.source_directory.join("receiver.lock")).unwrap();
    wrong = s.clone();
    wrong.expected_actor = "x".repeat(43);
    assert_eq!(import_page(&wrong).unwrap_err().code, "IDENTITY_MISMATCH");
    wrong = s.clone();
    wrong.expected_binding_digest = "c".repeat(64);
    assert_eq!(
        import_page(&wrong).unwrap_err().code,
        "LEGACY_DELIVERY_BINDING_MISMATCH"
    );
    let db = source(&s).unwrap();
    let marker: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM control WHERE key=?1)",
            [MARKER],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!marker);
    drop(db);
    assert!(!s.archive_directory.exists());
    // Correcting an unsubmitted typo must reuse the same chosen destination.
    assert_eq!(finish(&s)["state"], "LEGACY_EVIDENCE_IMPORTED");
}
#[test]
fn interruption_after_source_fence_resumes_exact_selection_and_keeps_one_archive_copy() {
    let (_root, s) = setup("RECEIVER", 2);
    let archive = Archive::open(&s).unwrap();
    // Force the archive commit to fail after the source retirement commits.
    archive.db.execute_batch("CREATE TRIGGER interrupt BEFORE INSERT ON legacy_records BEGIN SELECT RAISE(ABORT,'interruption'); END;").unwrap();
    drop(archive);
    assert_eq!(
        import_page(&s).unwrap_err().code,
        "LEGACY_DELIVERY_IMPORT_FAILED_RESUME_SAME_SELECTION"
    );
    let archive = Archive::open(&s).unwrap();
    archive.db.execute_batch("DROP TRIGGER interrupt;").unwrap();
    drop(archive);
    let done = finish(&s);
    assert_eq!(done["archived_records"], 4);
    assert_eq!(
        read_evidence(&s, "control:binding").unwrap()["evidence"]["original_json"],
        serde_json::to_string(&s.expected_binding_digest).unwrap()
    );
    assert_eq!(finish(&s), done);
    let mut changed = s.clone();
    changed.kind = "BRIDGE".into();
    assert_eq!(
        import_page(&changed).unwrap_err().code,
        "LEGACY_DELIVERY_SELECTION_CHANGED"
    );
}
#[test]
fn bridge_opaque_rows_and_exact_ledger_are_preserved_without_fabricated_scope() {
    let (_root, s) = setup("BRIDGE", 1);
    let raw = std::fs::read_to_string(s.source_directory.join("deliveries.json")).unwrap();
    let end = finish(&s);
    assert_eq!(end["archived_records"], 6);
    assert_eq!(
        read_evidence(&s, "bridge:original").unwrap()["evidence"]["original_json"],
        raw
    );
    let row = read_evidence(&s, "bridge:0").unwrap();
    assert_eq!(row["evidence"]["original"]["status"], "UNKNOWN");
    assert_eq!(row["evidence"]["original"]["key"], "opaque-original-key");
    assert_eq!(row["evidence"]["assurance"], "UNATTRIBUTED_LOCAL_ROW");
    assert!(row["evidence"].get("workspace_id").is_none());
    std::fs::remove_file(s.source_directory.join("deliveries.json")).unwrap();
    write_private(&s.source_directory.join("deliveries.json"), b"[]").unwrap();
    assert_eq!(
        import_page(&s).unwrap_err().code,
        "LEGACY_DELIVERY_RETIREMENT_MISMATCH"
    );
    // Already archived evidence remains readable despite a changed old file.
    assert_eq!(read_evidence(&s, "bridge:0").unwrap(), row);
}
#[test]
fn independent_import_owner_and_corrupt_ciphertext_are_refused() {
    let (_root, s) = setup("RECEIVER", 1);
    finish(&s);
    let archive = Archive::open(&s).unwrap();
    assert_eq!(
        import_page(&s).unwrap_err().code,
        "LEGACY_DELIVERY_IMPORT_ALREADY_RUNNING"
    );
    archive
        .db
        .execute(
            "UPDATE legacy_records SET evidence=zeroblob(length(evidence)) WHERE key='delivery:0'",
            [],
        )
        .unwrap();
    drop(archive);
    assert_eq!(
        read_evidence(&s, "delivery:0").unwrap_err().code,
        "LEGACY_DELIVERY_STATE_INVALID"
    );
}
#[cfg(unix)]
#[test]
fn symlinked_source_or_sidecar_never_changes_other_files() {
    let (root, s) = setup("RECEIVER", 1);
    let other = root.path().join("untouched");
    write_private(&other, b"original").unwrap();
    std::os::unix::fs::symlink(&other, s.source_directory.join("receiver.sqlite-wal")).unwrap();
    assert_eq!(
        import_page(&s).unwrap_err().code,
        "LEGACY_DELIVERY_SOURCE_NOT_PRIVATE"
    );
    assert_eq!(std::fs::read(&other).unwrap(), b"original");
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&s.source_directory, &alias).unwrap();
    let mut changed = s.clone();
    changed.source_directory = alias;
    assert_eq!(
        import_page(&changed).unwrap_err().code,
        "LEGACY_DELIVERY_STATE_INVALID"
    );
}
