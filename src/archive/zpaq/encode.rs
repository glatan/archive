//! zpaq archive encoding.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::compress::zpaq::decode::{
    BlockDecoder, ParsedBlockHeader, parse_block_header, parse_block_header_at,
};
use crate::compress::zpaq::encode::BlockEncoder;
use crate::compress::zpaq::models::model_zpaql;
use crate::compress::zpaq::zpaql::Zpaql;
use crate::error::Error;

use super::decode::{
    ZPAQ_JOURNAL_COMMENT_PREFIX, ZPAQ_JOURNAL_COMMIT_FILENAME, ZPAQ_JOURNAL_ENTRY_PREFIX,
    ZpaqEntry, decode, decode_journal_latest,
};

/// Builder for creating zpaq archives with multiple entries.
///
/// Supports both creating a fresh archive and appending additional blocks to
/// an existing archive whose parsed model/header can be reused.
///
/// # Examples
///
/// ```
/// use archive::archive::zpaq::{decode, encode};
///
/// let mut enc = encode::ZpaqEncoder::new(2);
/// enc.add_file("hello.txt", b"Hello!");
/// enc.add_file_with_comment("note.txt", "comment", b"World!");
/// let archive = enc.finish().unwrap();
/// let entries = decode::decode(&archive).unwrap();
/// assert_eq!(entries.len(), 2);
/// ```
#[derive(Debug)]
pub struct ZpaqEncoder {
    level: u32,
    entries: Vec<ZpaqEntry>,
}

#[derive(Debug, Clone)]
enum JournalOperation {
    Put(ZpaqEntry),
    Delete(Vec<u8>),
}

/// Builder for crate-local journaling transactions on top of the
/// multi-block archive layout.
///
/// Each call to [`Self::finish`] or [`Self::append_transaction`] emits one
/// committed transaction. The journal decoder applies only committed
/// transactions and ignores any uncommitted trailing operations.
#[derive(Debug)]
pub struct ZpaqJournalEncoder {
    level: u32,
    operations: Vec<JournalOperation>,
}

#[derive(Debug, Clone)]
enum ArchiveEditorConfig {
    BuiltInLevel(u32),
    Imported { zpaql: Box<Zpaql>, level: u8 },
}

/// Multi-step editor that materializes a final sequential-segment zpaq
/// archive view.
///
/// This workflow can import an existing plain archive or the latest committed
/// journal view, apply `push`/`put`/`delete` operations, and then emit one
/// rewritten single-block archive.
#[derive(Debug)]
pub struct ZpaqArchiveEditor {
    config: ArchiveEditorConfig,
    entries: Vec<ZpaqEntry>,
}

impl ZpaqEncoder {
    /// Create a new zpaq archive builder using compression level 1-3.
    pub const fn new(level: u32) -> Self {
        Self {
            level,
            entries: Vec::new(),
        }
    }

    /// Add a regular file with no comment.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_entry(name.as_bytes(), b"", data);
    }

    /// Add a regular file with a text comment.
    pub fn add_file_with_comment(&mut self, name: &str, comment: &str, data: &[u8]) {
        self.add_entry(name.as_bytes(), comment.as_bytes(), data);
    }

    /// Add a raw entry using byte-oriented filename/comment metadata.
    ///
    /// Metadata is encoded as NUL-terminated byte strings, so embedded NUL bytes
    /// are rejected by [`Self::finish`].
    pub fn add_entry(&mut self, filename: &[u8], comment: &[u8], data: &[u8]) {
        self.entries.push(ZpaqEntry {
            filename: filename.to_vec(),
            comment: comment.to_vec(),
            data: data.to_vec(),
        });
    }

    /// Finish the archive and return the encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidData`] when any filename or comment contains an
    /// embedded NUL byte, because zpaq archive metadata is emitted as
    /// NUL-terminated strings.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        let mut enc = builtin_block_encoder(self.level)?;
        enc.write_block_header(&mut output);
        encode_entries(&mut output, &mut enc, &self.entries)?;
        output.push(0xFF);
        Ok(output)
    }

    /// Append queued entries to an existing zpaq archive.
    ///
    /// For non-empty input, the existing archive's parsed block header/model is
    /// reused for a newly appended block (upstream journals add blocks rather
    /// than continuing a finished block, since predictor/arithmetic state would
    /// otherwise need to be reconstructed). The input must end exactly at the
    /// archive terminator without trailing bytes.
    pub fn append_to_archive(self, existing: &[u8]) -> Result<Vec<u8>, Error> {
        if existing.is_empty() {
            return self.finish();
        }

        let header = parse_block_header(existing)?;
        let archive_end = find_archive_end(existing, &header)?;
        let mut output = existing[..archive_end].to_vec();
        let mut enc = BlockEncoder::new(header.zpaql.clone(), header.level)?;
        enc.write_block_header(&mut output);
        encode_entries(&mut output, &mut enc, &self.entries)?;
        output.push(0xFF);
        Ok(output)
    }
}

impl Default for ZpaqEncoder {
    fn default() -> Self {
        Self::new(1)
    }
}

impl ZpaqJournalEncoder {
    /// Create a new journaling transaction builder using compression level 1-3.
    pub const fn new(level: u32) -> Self {
        Self {
            level,
            operations: Vec::new(),
        }
    }

    /// Queue a file add/update operation with no comment.
    pub fn put_file(&mut self, name: &str, data: &[u8]) {
        self.put_entry(name.as_bytes(), b"", data);
    }

    /// Queue a file add/update operation with a text comment.
    pub fn put_file_with_comment(&mut self, name: &str, comment: &str, data: &[u8]) {
        self.put_entry(name.as_bytes(), comment.as_bytes(), data);
    }

    /// Queue a raw add/update operation.
    pub fn put_entry(&mut self, filename: &[u8], comment: &[u8], data: &[u8]) {
        self.operations.push(JournalOperation::Put(ZpaqEntry {
            filename: filename.to_vec(),
            comment: comment.to_vec(),
            data: data.to_vec(),
        }));
    }

    /// Queue a delete operation for the given filename.
    pub fn delete_file(&mut self, name: &str) {
        self.delete_entry(name.as_bytes());
    }

    /// Queue a raw delete operation.
    pub fn delete_entry(&mut self, filename: &[u8]) {
        self.operations
            .push(JournalOperation::Delete(filename.to_vec()));
    }

    /// Finish a new archive containing one committed journaling transaction.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        let mut enc = builtin_block_encoder(self.level)?;
        enc.write_block_header(&mut output);
        encode_journal_operations(&mut output, &mut enc, &self.operations)?;
        output.push(0xFF);
        Ok(output)
    }

    /// Append one committed journaling transaction to an existing archive.
    ///
    /// The transaction is emitted as a new block using the existing
    /// archive's parsed model, matching upstream journaling where each
    /// update starts a fresh block.
    pub fn append_transaction(self, existing: &[u8]) -> Result<Vec<u8>, Error> {
        if existing.is_empty() {
            return self.finish();
        }

        let header = parse_block_header(existing)?;
        let archive_end = find_archive_end(existing, &header)?;
        let mut output = existing[..archive_end].to_vec();
        let mut enc = BlockEncoder::new(header.zpaql.clone(), header.level)?;
        enc.write_block_header(&mut output);
        encode_journal_operations(&mut output, &mut enc, &self.operations)?;
        output.push(0xFF);
        Ok(output)
    }
}

impl Default for ZpaqJournalEncoder {
    fn default() -> Self {
        Self::new(1)
    }
}

impl ZpaqArchiveEditor {
    /// Create a new editor using a built-in level 1-3 model.
    pub const fn new(level: u32) -> Self {
        Self {
            config: ArchiveEditorConfig::BuiltInLevel(level),
            entries: Vec::new(),
        }
    }

    /// Import an existing archive and reuse its parsed header/model
    /// when emitting the rewritten archive.
    pub fn from_archive(existing: &[u8]) -> Result<Self, Error> {
        if existing.is_empty() {
            return Ok(Self::new(1));
        }

        let header = parse_block_header(existing)?;
        find_archive_end(existing, &header)?;
        Ok(Self {
            config: ArchiveEditorConfig::Imported {
                zpaql: Box::new(header.zpaql.clone()),
                level: header.level,
            },
            entries: decode(existing)?,
        })
    }

    /// Import the latest committed view of a crate-local journal archive.
    ///
    /// The rewritten output is emitted as a plain sequential-segment archive.
    pub fn from_journal_latest(existing: &[u8]) -> Result<Self, Error> {
        if existing.is_empty() {
            return Ok(Self::new(1));
        }

        let header = parse_block_header(existing)?;
        find_archive_end(existing, &header)?;
        Ok(Self {
            config: ArchiveEditorConfig::Imported {
                zpaql: Box::new(header.zpaql.clone()),
                level: header.level,
            },
            entries: decode_journal_latest(existing)?,
        })
    }

    /// Append a raw entry without replacing existing entries of the same name.
    pub fn push_entry(&mut self, filename: &[u8], comment: &[u8], data: &[u8]) {
        self.entries.push(ZpaqEntry {
            filename: filename.to_vec(),
            comment: comment.to_vec(),
            data: data.to_vec(),
        });
    }

    /// Append a regular file with no comment.
    pub fn push_file(&mut self, name: &str, data: &[u8]) {
        self.push_entry(name.as_bytes(), b"", data);
    }

    /// Append a regular file with a text comment.
    pub fn push_file_with_comment(&mut self, name: &str, comment: &str, data: &[u8]) {
        self.push_entry(name.as_bytes(), comment.as_bytes(), data);
    }

    /// Upsert an entry by filename, replacing all existing entries with the
    /// same raw filename bytes and appending the new visible version at the end.
    pub fn put_entry(&mut self, filename: &[u8], comment: &[u8], data: &[u8]) {
        self.delete_entry(filename);
        self.push_entry(filename, comment, data);
    }

    /// Upsert a regular file with no comment.
    pub fn put_file(&mut self, name: &str, data: &[u8]) {
        self.put_entry(name.as_bytes(), b"", data);
    }

    /// Upsert a regular file with a text comment.
    pub fn put_file_with_comment(&mut self, name: &str, comment: &str, data: &[u8]) {
        self.put_entry(name.as_bytes(), comment.as_bytes(), data);
    }

    /// Delete all entries with the given raw filename bytes.
    pub fn delete_entry(&mut self, filename: &[u8]) {
        self.entries.retain(|entry| entry.filename != filename);
    }

    /// Delete all entries with the given filename.
    pub fn delete_file(&mut self, name: &str) {
        self.delete_entry(name.as_bytes());
    }

    /// Borrow the current materialized entry list.
    pub fn entries(&self) -> &[ZpaqEntry] {
        &self.entries
    }

    /// Finish the editor and emit one sequential-segment archive.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        let mut enc = match self.config {
            ArchiveEditorConfig::BuiltInLevel(level) => builtin_block_encoder(level)?,
            ArchiveEditorConfig::Imported { zpaql, level } => BlockEncoder::new(*zpaql, level)?,
        };
        enc.write_block_header(&mut output);
        encode_entries(&mut output, &mut enc, &self.entries)?;
        output.push(0xFF);
        Ok(output)
    }
}

impl Default for ZpaqArchiveEditor {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Spec §2: filename and comment are each 0..65535 bytes.
const MAX_METADATA_LEN: usize = 65535;

fn validate_metadata(value: &[u8], field: &'static str) -> Result<(), Error> {
    if value.contains(&0) {
        return Err(match field {
            "filename" => Error::InvalidData("zpaq: filename contains NUL"),
            "comment" => Error::InvalidData("zpaq: comment contains NUL"),
            _ => Error::InvalidData("zpaq: metadata contains NUL"),
        });
    }
    if value.len() > MAX_METADATA_LEN {
        return Err(match field {
            "filename" => Error::InvalidData("zpaq: filename too long"),
            "comment" => Error::InvalidData("zpaq: comment too long"),
            _ => Error::InvalidData("zpaq: metadata too long"),
        });
    }
    Ok(())
}

/// Spec §8 streaming: a segment comment must not end with the
/// journaling marker `jDC\x01`.  Upstream readers use that suffix to
/// detect journaling blocks, so emitting it on a streaming segment
/// would make the block be misinterpreted as JIDAC.
fn reject_jidac_marker(comment: &[u8]) -> Result<(), Error> {
    if comment.ends_with(b"jDC\x01") {
        return Err(Error::InvalidData(
            "zpaq: comment ends with reserved jDC marker",
        ));
    }
    Ok(())
}

fn builtin_block_encoder(level: u32) -> Result<BlockEncoder, Error> {
    let z = model_zpaql(level)?;
    let wire_level = 1 + u8::from(z.component_count() == 0);
    BlockEncoder::new(z, wire_level)
}

fn encode_entries(
    output: &mut Vec<u8>,
    enc: &mut BlockEncoder,
    entries: &[ZpaqEntry],
) -> Result<(), Error> {
    for entry in entries {
        validate_metadata(&entry.filename, "filename")?;
        validate_metadata(&entry.comment, "comment")?;
        reject_jidac_marker(&entry.comment)?;
        enc.encode_segment(output, &entry.filename, &entry.comment, &entry.data)?;
    }
    Ok(())
}

fn encode_journal_operations(
    output: &mut Vec<u8>,
    enc: &mut BlockEncoder,
    operations: &[JournalOperation],
) -> Result<(), Error> {
    for operation in operations {
        match operation {
            JournalOperation::Put(entry) => {
                validate_metadata(&entry.filename, "filename")?;
                validate_metadata(&entry.comment, "comment")?;
                reject_reserved_journal_filename(&entry.filename)?;

                let mut filename = ZPAQ_JOURNAL_ENTRY_PREFIX.to_vec();
                filename.extend_from_slice(&entry.filename);
                let mut comment = journal_comment(b'P');
                comment.extend_from_slice(&entry.comment);
                // Re-validate the assembled wire fields: the journal
                // prefixes add bytes that can push an otherwise legal
                // name/comment over the 65535-byte §2 limit, and the
                // §8 jDC marker check must see the final comment bytes.
                validate_metadata(&filename, "filename")?;
                validate_metadata(&comment, "comment")?;
                reject_jidac_marker(&comment)?;
                enc.encode_segment(output, &filename, &comment, &entry.data)?;
            }
            JournalOperation::Delete(filename) => {
                validate_metadata(filename, "filename")?;
                reject_reserved_journal_filename(filename)?;

                let mut encoded_filename = ZPAQ_JOURNAL_ENTRY_PREFIX.to_vec();
                encoded_filename.extend_from_slice(filename);
                validate_metadata(&encoded_filename, "filename")?;
                let comment = journal_comment(b'D');
                enc.encode_segment(output, &encoded_filename, &comment, &[])?;
            }
        }
    }

    enc.encode_segment(
        output,
        ZPAQ_JOURNAL_COMMIT_FILENAME,
        &journal_comment(b'C'),
        &[],
    )?;
    Ok(())
}

/// Decode every block of `input` and return the offset just past the
/// last block terminator.  Fails when trailing bytes remain.
fn find_archive_end(input: &[u8], header: &ParsedBlockHeader) -> Result<usize, Error> {
    // Bound total ZPAQL work across every block of the import scan.
    let budget = crate::compress::zpaq::zpaql::new_shared_budget();
    let mut end = decode_one_block(input, header, &budget)?;
    while let Some(next) = parse_block_header_at(input, end)? {
        end = decode_one_block(input, &next, &budget)?;
    }
    if end != input.len() {
        return Err(Error::InvalidData("zpaq: trailing bytes after archive end"));
    }
    Ok(end)
}

/// Run one block to its `255` terminator; returns the offset just past it.
fn decode_one_block(
    input: &[u8],
    header: &ParsedBlockHeader,
    budget: &crate::compress::zpaq::zpaql::CycleBudget,
) -> Result<usize, Error> {
    let mut dec = BlockDecoder::new(input, header, usize::MAX)?;
    dec.set_cycle_budget(budget.clone());
    while dec.next_segment()?.is_some() {}
    Ok(dec.end_pos())
}

fn reject_reserved_journal_filename(filename: &[u8]) -> Result<(), Error> {
    if filename.starts_with(ZPAQ_JOURNAL_ENTRY_PREFIX) || filename == ZPAQ_JOURNAL_COMMIT_FILENAME {
        return Err(Error::InvalidData(
            "zpaq: filename uses reserved journal prefix",
        ));
    }
    Ok(())
}

fn journal_comment(op: u8) -> Vec<u8> {
    let mut comment = ZPAQ_JOURNAL_COMMENT_PREFIX.to_vec();
    comment.push(op);
    comment
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::archive::zpaq::decode::decode;

    #[test]
    fn test_encode_empty_archive() {
        let archive = ZpaqEncoder::new(1).finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_roundtrip_entry_metadata() {
        let mut enc = ZpaqEncoder::new(3);
        enc.add_file_with_comment("hello.txt", "comment", b"payload");
        let archive = enc.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename_utf8(), Some("hello.txt"));
        assert_eq!(entries[0].comment_utf8(), Some("comment"));
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn test_rejects_nul_in_filename() {
        let mut enc = ZpaqEncoder::new(1);
        enc.add_entry(b"bad\0name", b"", b"payload");
        assert!(matches!(
            enc.finish(),
            Err(Error::InvalidData("zpaq: filename contains NUL"))
        ));
    }

    #[test]
    fn test_rejects_nul_in_comment() {
        let mut enc = ZpaqEncoder::new(1);
        enc.add_entry(b"ok", b"bad\0comment", b"payload");
        assert!(matches!(
            enc.finish(),
            Err(Error::InvalidData("zpaq: comment contains NUL"))
        ));
    }

    #[test]
    fn test_rejects_oversized_filename() {
        let mut enc = ZpaqEncoder::new(1);
        enc.add_entry(&vec![b'a'; 65536], b"", b"payload");
        assert!(matches!(
            enc.finish(),
            Err(Error::InvalidData("zpaq: filename too long"))
        ));

        // The 65535-byte boundary is still accepted.
        let mut enc = ZpaqEncoder::new(1);
        enc.add_entry(&vec![b'a'; 65535], b"", b"payload");
        let archive = enc.finish().unwrap();
        assert_eq!(decode(&archive).unwrap()[0].filename.len(), 65535);
    }

    #[test]
    fn test_rejects_oversized_comment() {
        let mut enc = ZpaqEncoder::new(1);
        enc.add_entry(b"ok", &vec![b'c'; 65536], b"payload");
        assert!(matches!(
            enc.finish(),
            Err(Error::InvalidData("zpaq: comment too long"))
        ));
    }

    #[test]
    fn test_journal_rejects_oversized_encoded_filename() {
        // The "@zpaqj1:" prefix pushes a near-limit filename over
        // 65535 bytes on the wire.
        let mut journal = ZpaqJournalEncoder::new(1);
        journal.put_entry(&vec![b'a'; 65535], b"", b"payload");
        assert!(matches!(
            journal.finish(),
            Err(Error::InvalidData("zpaq: filename too long"))
        ));
    }

    #[test]
    fn test_rejects_comment_ending_jdc_marker() {
        // Spec §8: a streaming segment comment must not end with
        // "jDC\x01" (the JIDAC journaling marker).
        let mut enc = ZpaqEncoder::new(1);
        enc.add_entry(b"ok", b"note jDC\x01", b"payload");
        assert!(matches!(
            enc.finish(),
            Err(Error::InvalidData(
                "zpaq: comment ends with reserved jDC marker"
            ))
        ));

        // The same applies to journal put operations, where the
        // emitted comment is prefix + op + user comment.
        let mut journal = ZpaqJournalEncoder::new(1);
        journal.put_entry(b"ok", b"note jDC\x01", b"payload");
        assert!(matches!(
            journal.finish(),
            Err(Error::InvalidData(
                "zpaq: comment ends with reserved jDC marker"
            ))
        ));
    }

    #[test]
    fn test_archive_encoder_clamps_public_level_range() {
        let mut low = ZpaqEncoder::new(0);
        low.add_file("low.txt", b"payload");
        let low_archive = low.finish().unwrap();

        let mut high = ZpaqEncoder::new(99);
        high.add_file("high.txt", b"payload");
        let high_archive = high.finish().unwrap();

        assert_eq!(&low_archive[13..16], b"zPQ");
        assert_eq!(low_archive[16], 1);
        assert_eq!(high_archive[16], 1);
        assert_ne!(low_archive, high_archive);
        assert_eq!(decode(&low_archive).unwrap()[0].data, b"payload");
        assert_eq!(decode(&high_archive).unwrap()[0].data, b"payload");
    }

    #[test]
    fn test_append_to_archive_preserves_existing_entries_and_header() {
        let mut base = ZpaqEncoder::new(1);
        base.add_file("base.txt", b"base");
        let existing = base.finish().unwrap();

        let mut append = ZpaqEncoder::new(3);
        append.add_file_with_comment("extra.txt", "note", b"extra");
        let archive = append.append_to_archive(&existing).unwrap();

        assert_eq!(&archive[13..16], b"zPQ");
        assert_eq!(archive[16], 1);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename_utf8(), Some("base.txt"));
        assert_eq!(entries[0].data, b"base");
        assert_eq!(entries[1].filename_utf8(), Some("extra.txt"));
        assert_eq!(entries[1].comment_utf8(), Some("note"));
        assert_eq!(entries[1].data, b"extra");
    }

    #[test]
    fn test_append_to_archive_rejects_trailing_bytes() {
        let mut base = ZpaqEncoder::new(1);
        base.add_file("base.txt", b"base");
        let mut existing = base.finish().unwrap();
        existing.extend_from_slice(b"junk");

        let mut append = ZpaqEncoder::new(1);
        append.add_file("extra.txt", b"extra");
        assert!(matches!(
            append.append_to_archive(&existing),
            Err(Error::InvalidData("zpaq: trailing bytes after archive end"))
        ));
    }

    #[test]
    fn test_journal_encoder_appends_committed_transaction() {
        let mut journal = ZpaqJournalEncoder::new(2);
        journal.put_file("hello.txt", b"hello");
        journal.put_file_with_comment("note.txt", "memo", b"payload");
        let archive = journal.finish().unwrap();
        let latest = super::super::decode::decode_journal_latest(&archive).unwrap();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].filename_utf8(), Some("hello.txt"));
        assert_eq!(latest[0].data, b"hello");
        assert_eq!(latest[1].comment_utf8(), Some("memo"));
        assert_eq!(latest[1].data, b"payload");
    }

    #[test]
    fn test_journal_encoder_rejects_reserved_filename_prefix() {
        let mut journal = ZpaqJournalEncoder::new(1);
        let mut reserved = ZPAQ_JOURNAL_ENTRY_PREFIX.to_vec();
        reserved.extend_from_slice(b"bad");
        journal.put_entry(&reserved, b"", b"payload");
        assert!(matches!(
            journal.finish(),
            Err(Error::InvalidData(
                "zpaq: filename uses reserved journal prefix"
            ))
        ));
    }

    #[test]
    fn test_archive_editor_from_archive_put_and_delete() {
        let mut base = ZpaqEncoder::new(2);
        base.add_file("base.txt", b"base");
        base.add_file_with_comment("extra.txt", "old", b"extra");
        let archive = base.finish().unwrap();

        let mut editor = ZpaqArchiveEditor::from_archive(&archive).unwrap();
        editor.put_file_with_comment("extra.txt", "new", b"updated");
        editor.delete_file("base.txt");
        editor.push_file("tail.txt", b"tail");
        let rewritten = editor.finish().unwrap();
        let entries = decode(&rewritten).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename_utf8(), Some("extra.txt"));
        assert_eq!(entries[0].comment_utf8(), Some("new"));
        assert_eq!(entries[0].data, b"updated");
        assert_eq!(entries[1].filename_utf8(), Some("tail.txt"));
        assert_eq!(entries[1].data, b"tail");
    }

    #[test]
    fn test_archive_editor_from_journal_latest_materializes_plain_archive() {
        let mut tx1 = ZpaqJournalEncoder::new(1);
        tx1.put_file("alpha.txt", b"one");
        let mut archive = tx1.finish().unwrap();

        let mut tx2 = ZpaqJournalEncoder::new(3);
        tx2.put_file_with_comment("alpha.txt", "v2", b"two");
        tx2.put_file("beta.txt", b"beta");
        archive = tx2.append_transaction(&archive).unwrap();

        let mut editor = ZpaqArchiveEditor::from_journal_latest(&archive).unwrap();
        editor.delete_file("beta.txt");
        let rewritten = editor.finish().unwrap();
        let plain = decode(&rewritten).unwrap();

        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].filename_utf8(), Some("alpha.txt"));
        assert_eq!(plain[0].comment_utf8(), Some("v2"));
        assert_eq!(plain[0].data, b"two");
    }
}
