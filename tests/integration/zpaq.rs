use super::*;

#[test]
fn test_zpaq_archive_multi_entry_roundtrip() {
    let mut encoder = zpaq::encode::ZpaqEncoder::new(2);
    encoder.add_file("hello.txt", b"hello from zpaq archive");
    encoder.add_entry(b"bin-name-\xff", b"\xffnote", b"\x00\x01\x02payload");

    let archive = encoder.finish().unwrap();
    let entries = zpaq::decode::decode(&archive).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].filename_utf8(), Some("hello.txt"));
    assert_eq!(entries[0].comment_utf8(), Some(""));
    assert_eq!(entries[0].data, b"hello from zpaq archive");
    assert_eq!(entries[1].filename, b"bin-name-\xff");
    assert_eq!(entries[1].filename_utf8(), None);
    assert_eq!(entries[1].comment, b"\xffnote");
    assert_eq!(entries[1].comment_utf8(), None);
    assert_eq!(entries[1].data, b"\x00\x01\x02payload");
}

#[test]
fn test_zpaq_archive_empty_roundtrip() {
    let archive = zpaq::encode::ZpaqEncoder::new(1).finish().unwrap();
    let entries = zpaq::decode::decode(&archive).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_zpaq_archive_rejects_nul_metadata() {
    let mut encoder = zpaq::encode::ZpaqEncoder::new(1);
    encoder.add_entry(b"bad\0name", b"", b"payload");
    assert!(matches!(
        encoder.finish(),
        Err(archive::error::Error::InvalidData(
            "zpaq: filename contains NUL"
        ))
    ));
}

#[test]
fn test_zpaq_archive_accepts_empty_filename() {
    let mut encoder = zpaq::encode::ZpaqEncoder::new(1);
    encoder.add_entry(b"", b"note", b"payload");
    let archive = encoder.finish().unwrap();
    let entries = zpaq::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].filename, b"");
    assert_eq!(entries[0].comment_utf8(), Some("note"));
    assert_eq!(entries[0].data, b"payload");
}

#[test]
fn test_zpaq_archive_roundtrip_mixed_empty_payload_entries() {
    let mut encoder = zpaq::encode::ZpaqEncoder::new(3);
    encoder.add_entry(b"", b"", b"");
    encoder.add_file_with_comment("note.txt", "comment", b"");
    encoder.add_entry(b"bin-\xff", b"\xffmemo", b"payload");

    let archive = encoder.finish().unwrap();
    let entries = zpaq::decode::decode(&archive).unwrap();

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].filename, b"");
    assert_eq!(entries[0].comment, b"");
    assert_eq!(entries[0].data, b"");
    assert_eq!(entries[1].filename_utf8(), Some("note.txt"));
    assert_eq!(entries[1].comment_utf8(), Some("comment"));
    assert_eq!(entries[1].data, b"");
    assert_eq!(entries[2].filename, b"bin-\xff");
    assert_eq!(entries[2].comment, b"\xffmemo");
    assert_eq!(entries[2].data, b"payload");
}

#[test]
fn test_zpaq_archive_append_to_existing_roundtrip() {
    let mut base = zpaq::encode::ZpaqEncoder::new(1);
    base.add_file("base.txt", b"base payload");
    let existing = base.finish().unwrap();

    let mut append = zpaq::encode::ZpaqEncoder::new(3);
    append.add_file_with_comment("extra.txt", "note", b"extra payload");
    let archive = append.append_to_archive(&existing).unwrap();
    let entries = zpaq::decode::decode(&archive).unwrap();

    assert_eq!(&archive[13..16], b"zPQ");
    assert_eq!(archive[16], 1); // wire level byte (modeled stream)
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].filename_utf8(), Some("base.txt"));
    assert_eq!(entries[0].data, b"base payload");
    assert_eq!(entries[1].filename_utf8(), Some("extra.txt"));
    assert_eq!(entries[1].comment_utf8(), Some("note"));
    assert_eq!(entries[1].data, b"extra payload");
}

#[test]
fn test_zpaq_journal_latest_view_roundtrip() {
    let mut journal = zpaq::encode::ZpaqJournalEncoder::new(1);
    journal.put_file("base.txt", b"base payload");
    let mut archive = journal.finish().unwrap();

    let mut update = zpaq::encode::ZpaqJournalEncoder::new(3);
    update.put_file_with_comment("base.txt", "v2", b"updated payload");
    update.put_file("extra.txt", b"extra payload");
    archive = update.append_transaction(&archive).unwrap();

    let latest = zpaq::decode::decode_journal_latest(&archive).unwrap();
    assert_eq!(latest.len(), 2);
    assert_eq!(latest[0].filename_utf8(), Some("base.txt"));
    assert_eq!(latest[0].comment_utf8(), Some("v2"));
    assert_eq!(latest[0].data, b"updated payload");
    assert_eq!(latest[1].filename_utf8(), Some("extra.txt"));
    assert_eq!(latest[1].data, b"extra payload");
}

#[test]
fn test_zpaq_journal_delete_visibility() {
    let mut journal = zpaq::encode::ZpaqJournalEncoder::new(1);
    journal.put_file("base.txt", b"base payload");
    journal.put_file("extra.txt", b"extra payload");
    let mut archive = journal.finish().unwrap();

    let mut delete = zpaq::encode::ZpaqJournalEncoder::new(2);
    delete.delete_file("extra.txt");
    archive = delete.append_transaction(&archive).unwrap();

    let latest = zpaq::decode::decode_journal_latest(&archive).unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].filename_utf8(), Some("base.txt"));
    assert_eq!(latest[0].data, b"base payload");
}

#[test]
fn test_zpaq_archive_editor_rewrites_imported_archive() {
    let mut base = zpaq::encode::ZpaqEncoder::new(2);
    base.add_file("base.txt", b"base payload");
    base.add_file_with_comment("keep.txt", "old", b"keep payload");
    let archive = base.finish().unwrap();

    let mut editor = zpaq::encode::ZpaqArchiveEditor::from_archive(&archive).unwrap();
    editor.put_file_with_comment("keep.txt", "new", b"updated payload");
    editor.delete_file("base.txt");
    editor.push_file("tail.txt", b"tail payload");
    let rewritten = editor.finish().unwrap();

    let entries = zpaq::decode::decode(&rewritten).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].filename_utf8(), Some("keep.txt"));
    assert_eq!(entries[0].comment_utf8(), Some("new"));
    assert_eq!(entries[0].data, b"updated payload");
    assert_eq!(entries[1].filename_utf8(), Some("tail.txt"));
    assert_eq!(entries[1].data, b"tail payload");
}

#[test]
fn test_zpaq_archive_editor_materializes_journal_latest_view() {
    let mut tx1 = zpaq::encode::ZpaqJournalEncoder::new(1);
    tx1.put_file("alpha.txt", b"one");
    let mut archive = tx1.finish().unwrap();

    let mut tx2 = zpaq::encode::ZpaqJournalEncoder::new(1);
    tx2.put_file_with_comment("alpha.txt", "v2", b"two");
    tx2.put_file("beta.txt", b"beta");
    archive = tx2.append_transaction(&archive).unwrap();

    let mut editor = zpaq::encode::ZpaqArchiveEditor::from_journal_latest(&archive).unwrap();
    editor.delete_file("beta.txt");
    let rewritten = editor.finish().unwrap();

    let latest = zpaq::decode::decode(&rewritten).unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].filename_utf8(), Some("alpha.txt"));
    assert_eq!(latest[0].comment_utf8(), Some("v2"));
    assert_eq!(latest[0].data, b"two");
}
