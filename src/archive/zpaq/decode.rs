//! zpaq archive decoding.

use alloc::vec::Vec;

use crate::compress::zpaq::decode::{BlockDecoder, DecodedSegment, parse_block_header_at};
use crate::error::Error;

pub(crate) const ZPAQ_JOURNAL_ENTRY_PREFIX: &[u8] = b"@zpaqj1:";
pub(crate) const ZPAQ_JOURNAL_COMMIT_FILENAME: &[u8] = b"@zpaqj1:commit";
pub(crate) const ZPAQ_JOURNAL_COMMENT_PREFIX: &[u8] = b"@zpaqj1-op:";

/// A single entry in a zpaq archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZpaqEntry {
    /// Raw filename bytes from the archive.
    pub filename: Vec<u8>,
    /// Raw comment bytes from the archive.
    pub comment: Vec<u8>,
    /// Decompressed payload.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for ZpaqEntry {
    fn name(&self) -> &str {
        core::str::from_utf8(&self.filename).unwrap_or("")
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl ZpaqEntry {
    /// Returns the filename as UTF-8 when valid.
    pub fn filename_utf8(&self) -> Option<&str> {
        core::str::from_utf8(&self.filename).ok()
    }

    /// Returns the comment as UTF-8 when valid.
    pub fn comment_utf8(&self) -> Option<&str> {
        core::str::from_utf8(&self.comment).ok()
    }
}

/// One committed journaling snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZpaqJournalVersion {
    /// Sequential commit number starting at 1.
    pub version: usize,
    /// Visible entries after applying the committed transaction.
    pub entries: Vec<ZpaqEntry>,
}

/// Decode a zpaq archive from a byte slice, yielding all entries.
///
/// # Examples
///
/// ```
/// use archive::archive::zpaq::{decode, encode};
///
/// let mut enc = encode::ZpaqEncoder::new(2);
/// enc.add_file("a.txt", b"aaa");
/// enc.add_file_with_comment("b.txt", "note", b"bbb");
/// let archive = enc.finish().unwrap();
/// let entries = decode::decode(&archive).unwrap();
/// assert_eq!(entries.len(), 2);
/// assert_eq!(entries[0].filename_utf8(), Some("a.txt"));
/// assert_eq!(entries[1].comment_utf8(), Some("note"));
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<ZpaqEntry>, Error> {
    let mut entries = Vec::new();
    for_each_segment(input, |segment| {
        entries.push(ZpaqEntry {
            filename: segment.filename.clone(),
            comment: segment.comment.clone(),
            data: segment.data.clone(),
        });
        Ok(())
    })?;
    Ok(entries)
}

/// Run `f` over every segment of every block in `input`, in stream
/// order. Predictor/arithmetic state is shared across the segments of
/// each block exactly like upstream `Decompresser`.
fn for_each_segment(
    input: &[u8],
    mut f: impl FnMut(&DecodedSegment) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut start = 0;
    while let Some(header) = parse_block_header_at(input, start)? {
        let mut block = BlockDecoder::new(input, &header, usize::MAX)?;
        while let Some(segment) = block.next_segment()? {
            f(&segment)?;
        }
        start = block.end_pos();
    }
    if start == 0 {
        return Err(Error::InvalidData("zpaq: no block locator found"));
    }
    Ok(())
}

/// Decode the latest visible view of a crate-local journaling archive.
///
/// Non-journal entries are treated as already committed singleton puts so that
/// existing non-journal archives remain readable through this helper.
pub fn decode_journal_latest(input: &[u8]) -> Result<Vec<ZpaqEntry>, Error> {
    let mut versions = decode_journal_versions(input)?;
    Ok(versions
        .pop()
        .map_or_else(Vec::new, |version| version.entries))
}

/// Decode all committed journaling snapshots in commit order.
pub fn decode_journal_versions(input: &[u8]) -> Result<Vec<ZpaqJournalVersion>, Error> {
    let mut visible = Vec::new();
    let mut pending = Vec::new();
    let mut versions = Vec::new();

    let mut saw_segment = false;
    let result = for_each_segment(input, |segment| {
        saw_segment = true;
        match parse_journal_segment(segment)? {
            JournalSegment::Ordinary(entry) => {
                if !pending.is_empty() {
                    return Err(Error::InvalidData(
                        "zpaq: mixed journal and non-journal segments in pending transaction",
                    ));
                }
                apply_put(&mut visible, entry);
                versions.push(ZpaqJournalVersion {
                    version: versions.len() + 1,
                    entries: visible.clone(),
                });
            }
            JournalSegment::JournalPut(entry) => pending.push(JournalOperation::Put(entry)),
            JournalSegment::JournalDelete(filename) => {
                pending.push(JournalOperation::Delete(filename))
            }
            JournalSegment::Commit => {
                apply_pending(&mut visible, &pending);
                pending.clear();
                versions.push(ZpaqJournalVersion {
                    version: versions.len() + 1,
                    entries: visible.clone(),
                });
            }
        }
        Ok(())
    });
    match result {
        Ok(()) => {}
        // A truncated tail (e.g. an interrupted append) leaves the last
        // committed versions readable, matching prior behavior.
        Err(Error::UnexpectedEof) if saw_segment => {}
        Err(err) => return Err(err),
    }

    Ok(versions)
}

enum JournalOperation {
    Put(ZpaqEntry),
    Delete(Vec<u8>),
}

enum JournalSegment {
    Ordinary(ZpaqEntry),
    JournalPut(ZpaqEntry),
    JournalDelete(Vec<u8>),
    Commit,
}

fn parse_journal_segment(
    segment: &crate::compress::zpaq::decode::DecodedSegment,
) -> Result<JournalSegment, Error> {
    if segment.filename == ZPAQ_JOURNAL_COMMIT_FILENAME {
        if segment.comment == journal_comment(b'C') && segment.data.is_empty() {
            return Ok(JournalSegment::Commit);
        }
        return Err(Error::InvalidData("zpaq: invalid journal commit marker"));
    }

    if !segment.filename.starts_with(ZPAQ_JOURNAL_ENTRY_PREFIX) {
        return Ok(JournalSegment::Ordinary(ZpaqEntry {
            filename: segment.filename.clone(),
            comment: segment.comment.clone(),
            data: segment.data.clone(),
        }));
    }

    if segment.comment.len() < ZPAQ_JOURNAL_COMMENT_PREFIX.len() + 1
        || !segment.comment.starts_with(ZPAQ_JOURNAL_COMMENT_PREFIX)
    {
        return Err(Error::InvalidData("zpaq: invalid journal segment comment"));
    }

    let filename = segment.filename[ZPAQ_JOURNAL_ENTRY_PREFIX.len()..].to_vec();
    match segment.comment[ZPAQ_JOURNAL_COMMENT_PREFIX.len()] {
        b'P' => Ok(JournalSegment::JournalPut(ZpaqEntry {
            filename,
            comment: segment.comment[ZPAQ_JOURNAL_COMMENT_PREFIX.len() + 1..].to_vec(),
            data: segment.data.clone(),
        })),
        b'D' => {
            if !segment.data.is_empty()
                || segment.comment.len() != ZPAQ_JOURNAL_COMMENT_PREFIX.len() + 1
            {
                return Err(Error::InvalidData("zpaq: invalid journal delete segment"));
            }
            Ok(JournalSegment::JournalDelete(filename))
        }
        _ => Err(Error::InvalidData("zpaq: invalid journal operation")),
    }
}

fn apply_pending(visible: &mut Vec<ZpaqEntry>, pending: &[JournalOperation]) {
    for operation in pending {
        match operation {
            JournalOperation::Put(entry) => apply_put(visible, entry.clone()),
            JournalOperation::Delete(filename) => {
                if let Some(index) = visible.iter().position(|entry| entry.filename == *filename) {
                    visible.remove(index);
                }
            }
        }
    }
}

fn apply_put(visible: &mut Vec<ZpaqEntry>, entry: ZpaqEntry) {
    if let Some(index) = visible
        .iter()
        .position(|existing| existing.filename == entry.filename)
    {
        visible.remove(index);
    }
    visible.push(entry);
}

fn journal_comment(op: u8) -> Vec<u8> {
    let mut comment = ZPAQ_JOURNAL_COMMENT_PREFIX.to_vec();
    comment.push(op);
    comment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::zpaq::encode::{ZpaqEncoder, ZpaqJournalEncoder};

    #[test]
    fn test_decode_two_entries() {
        let mut enc = ZpaqEncoder::new(2);
        enc.add_file("a.txt", b"aaa");
        enc.add_file_with_comment("b.txt", "note", b"bbb");
        let archive = enc.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename_utf8(), Some("a.txt"));
        assert_eq!(entries[0].data, b"aaa");
        assert_eq!(entries[1].filename_utf8(), Some("b.txt"));
        assert_eq!(entries[1].comment_utf8(), Some("note"));
        assert_eq!(entries[1].data, b"bbb");
    }

    #[test]
    fn test_decode_preserves_empty_payload_entries() {
        let mut enc = ZpaqEncoder::new(3);
        enc.add_entry(b"", b"", b"");
        enc.add_file_with_comment("note.txt", "comment", b"");
        enc.add_entry(b"bin-\xff", b"\xffmemo", b"payload");
        let archive = enc.finish().unwrap();
        let entries = decode(&archive).unwrap();
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
    fn test_decode_journal_latest_applies_put_update_and_delete() {
        let mut journal = ZpaqJournalEncoder::new(1);
        journal.put_file("alpha.txt", b"one");
        let mut archive = journal.finish().unwrap();

        let mut update = ZpaqJournalEncoder::new(3);
        update.put_file_with_comment("alpha.txt", "v2", b"two");
        update.put_file("beta.txt", b"beta");
        archive = update.append_transaction(&archive).unwrap();

        let mut delete = ZpaqJournalEncoder::new(2);
        delete.delete_file("beta.txt");
        archive = delete.append_transaction(&archive).unwrap();

        let latest = decode_journal_latest(&archive).unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].filename_utf8(), Some("alpha.txt"));
        assert_eq!(latest[0].comment_utf8(), Some("v2"));
        assert_eq!(latest[0].data, b"two");
    }

    #[test]
    fn test_decode_journal_versions_ignores_uncommitted_tail() {
        let mut journal = ZpaqJournalEncoder::new(1);
        journal.put_file("alpha.txt", b"one");
        let mut archive = journal.finish().unwrap();

        // Build a second block holding one journal put without its
        // commit segment: take the tail archive's first segment and
        // terminate its block immediately.
        let mut tail = ZpaqJournalEncoder::new(1);
        tail.put_file("beta.txt", b"two");
        let tail_archive = tail.finish().unwrap();
        let tail_header = crate::compress::zpaq::decode::parse_block_header(&tail_archive).unwrap();
        let mut tail_dec = BlockDecoder::new(&tail_archive, &tail_header, usize::MAX).unwrap();
        assert!(tail_dec.next_segment().unwrap().is_some());
        let first_seg_end = tail_dec.end_pos();
        let mut tail_block = tail_archive[..first_seg_end].to_vec();
        tail_block.push(0xFF);
        archive.extend_from_slice(&tail_block);

        let versions = decode_journal_versions(&archive).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].entries[0].filename_utf8(), Some("alpha.txt"));
        let latest = decode_journal_latest(&archive).unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].filename_utf8(), Some("alpha.txt"));
    }

    #[test]
    fn test_decode_journal_latest_treats_plain_archive_as_committed_puts() {
        let mut enc = ZpaqEncoder::new(2);
        enc.add_file("a.txt", b"aaa");
        enc.add_file("b.txt", b"bbb");
        let archive = enc.finish().unwrap();

        let latest = decode_journal_latest(&archive).unwrap();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].filename_utf8(), Some("a.txt"));
        assert_eq!(latest[1].filename_utf8(), Some("b.txt"));
    }

    #[test]
    fn test_archive_entry_trait() {
        use crate::traits::ArchiveEntry;
        let mut enc = super::super::encode::ZpaqEncoder::new(2);
        enc.add_file("hello.txt", b"Hello!");
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
    }

    #[test]
    fn test_archive_codec_decode_roundtrip() {
        use crate::archive::zpaq::ZpaqCodec;
        use crate::traits::{ArchiveDecode, ArchiveEntry};

        let mut enc = super::super::encode::ZpaqEncoder::new(2);
        enc.add_file("hello.txt", b"Hello!");
        enc.add_file("world.txt", b"World!");
        let archive = enc.finish().unwrap();

        let codec = ZpaqCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
        assert_eq!(entries[1].name(), "world.txt");
        assert_eq!(entries[1].data(), b"World!");
    }

    #[test]
    fn test_archive_entry_empty_data() {
        use crate::archive::zpaq::ZpaqCodec;
        use crate::traits::{ArchiveDecode, ArchiveEntry};

        let mut enc = super::super::encode::ZpaqEncoder::new(2);
        enc.add_file("empty.txt", b"");
        let archive = enc.finish().unwrap();

        let codec = ZpaqCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "empty.txt");
        assert_eq!(entries[0].data(), b"");
    }

    #[test]
    fn test_archive_multiple_entries() {
        use crate::archive::zpaq::ZpaqCodec;
        use crate::traits::{ArchiveDecode, ArchiveEntry};

        let mut enc = super::super::encode::ZpaqEncoder::new(1);
        for i in 0..12 {
            let name = alloc::format!("file_{i}.txt");
            let data = alloc::format!("Content of file {i}");
            enc.add_file(&name, data.as_bytes());
        }
        let archive = enc.finish().unwrap();

        let codec = ZpaqCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 12);
        for (i, entry) in entries.iter().enumerate() {
            let expected_name = alloc::format!("file_{i}.txt");
            let expected_data = alloc::format!("Content of file {i}");
            assert_eq!(entry.name(), expected_name);
            assert_eq!(entry.data(), expected_data.as_bytes());
        }
    }
}
