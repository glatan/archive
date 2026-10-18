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
    for_each_segment(input, 0, |segment| {
        push_segment_entry(&mut entries, segment);
        Ok(())
    })?;
    Ok(entries)
}

/// Decode with a maximum total payload size limit across all entries.
///
/// Returns [`Error::OutputLimitExceeded`] if the combined decompressed
/// output would exceed `max_output` bytes, or if the arithmetic
/// decoder produces more than `max_output` bytes of pre-postprocessing
/// data (see [`crate::compress::zpaq::decode::decode_bounded`]). A
/// `max_output` of 0 means unlimited.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<ZpaqEntry>, Error> {
    let mut entries = Vec::new();
    for_each_segment(input, max_output, |segment| {
        push_segment_entry(&mut entries, segment);
        Ok(())
    })?;
    Ok(entries)
}

/// Append a decoded segment to `entries` following the streaming-format
/// continuation rule: a segment with an empty filename continues the
/// previous file, so its payload is appended to the last entry and its
/// own comment is dropped. An empty filename with no preceding entry
/// (the first segment of the archive) stays a standalone anonymous
/// entry, matching the spec's "no file name is specified" case.
fn push_segment_entry(entries: &mut Vec<ZpaqEntry>, segment: &DecodedSegment) {
    if segment.filename.is_empty()
        && let Some(last) = entries.last_mut()
    {
        last.data.extend_from_slice(&segment.data);
        return;
    }
    entries.push(ZpaqEntry {
        filename: segment.filename.clone(),
        comment: segment.comment.clone(),
        data: segment.data.clone(),
    });
}

/// Run `f` over every segment of every block in `input`, in stream
/// order. Predictor/arithmetic state is shared across the segments of
/// each block exactly like upstream `Decompresser`. `max_output` bounds
/// the combined payload bytes emitted across all blocks (0 = unlimited);
/// it also bounds the bytes produced by the arithmetic decoder so a
/// zero-output postprocessor cannot stall the decode (see
/// [`crate::compress::zpaq::decode::decode_bounded`]).
fn for_each_segment(
    input: &[u8],
    max_output: usize,
    mut f: impl FnMut(&DecodedSegment) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut start = 0;
    let mut emitted_total = 0usize;
    let mut decoded_total = 0usize;
    // Bound total ZPAQL work across every block of this decode.
    let budget = crate::compress::zpaq::zpaql::new_shared_budget();
    while let Some(header) = parse_block_header_at(input, start)? {
        let remaining = if max_output == 0 {
            usize::MAX
        } else {
            max_output.saturating_sub(emitted_total)
        };
        let mut block = BlockDecoder::new(input, &header, remaining)?;
        block.set_cycle_budget(budget.clone());
        if max_output != 0 {
            block.set_max_decoded(max_output.saturating_sub(decoded_total));
        }
        while let Some(segment) = block.next_segment()? {
            emitted_total = emitted_total.saturating_add(segment.data.len());
            f(&segment)?;
        }
        decoded_total = decoded_total.saturating_add(block.decoded());
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
    let (arena, versions) = journal_snapshots(input)?;
    Ok(versions
        .last()
        .map(|spans| materialize_spans(&arena, spans))
        .unwrap_or_default())
}

/// Decode all committed journaling snapshots in commit order.
pub fn decode_journal_versions(input: &[u8]) -> Result<Vec<ZpaqJournalVersion>, Error> {
    let (arena, versions) = journal_snapshots(input)?;
    Ok(versions
        .into_iter()
        .enumerate()
        .map(|(index, spans)| ZpaqJournalVersion {
            version: index + 1,
            entries: materialize_spans(&arena, &spans),
        })
        .collect())
}

/// Filename and comment plus a range into the shared payload arena.
/// Snapshots clone this list, not the bytes. Payloads are copied once,
/// when a returned [`ZpaqEntry`] is built.
#[derive(Clone)]
struct FileSpan {
    filename: Vec<u8>,
    comment: Vec<u8>,
    start: usize,
    end: usize,
}

fn journal_snapshots(input: &[u8]) -> Result<(Vec<u8>, Vec<Vec<FileSpan>>), Error> {
    let mut arena = Vec::new();
    let mut visible: Vec<FileSpan> = Vec::new();
    let mut pending = Vec::new();
    let mut versions = Vec::new();

    let mut saw_segment = false;
    let result = for_each_segment(input, 0, |segment| {
        saw_segment = true;
        match parse_journal_segment(segment)? {
            JournalSegment::Ordinary(entry) => {
                if !pending.is_empty() {
                    return Err(Error::InvalidData(
                        "zpaq: mixed journal and non-journal segments in pending transaction",
                    ));
                }
                // Empty filename segments continue the previous file,
                // matching the streaming-format rule in `decode`.
                if entry.filename.is_empty()
                    && let Some(last) = visible.last_mut()
                {
                    extend_span(&mut arena, last, &entry.data);
                } else {
                    apply_put(&mut visible, entry, &mut arena);
                }
                versions.push(visible.clone());
            }
            JournalSegment::JournalPut(entry) => pending.push(JournalOperation::Put(entry)),
            JournalSegment::JournalDelete(filename) => {
                pending.push(JournalOperation::Delete(filename))
            }
            JournalSegment::Commit => {
                apply_pending(&mut visible, &pending, &mut arena);
                pending.clear();
                versions.push(visible.clone());
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

    Ok((arena, versions))
}

fn materialize_spans(arena: &[u8], spans: &[FileSpan]) -> Vec<ZpaqEntry> {
    spans
        .iter()
        .map(|span| ZpaqEntry {
            filename: span.filename.clone(),
            comment: span.comment.clone(),
            data: arena[span.start..span.end].to_vec(),
        })
        .collect()
}

/// Append `extra` without rewriting bytes an earlier snapshot still names.
/// When this span already owns the arena tail, the new bytes are written
/// after the old end. Otherwise the previous payload is copied to the tail
/// and then extended, leaving the old range intact.
fn extend_span(arena: &mut Vec<u8>, span: &mut FileSpan, extra: &[u8]) {
    if span.end == arena.len() {
        arena.extend_from_slice(extra);
        span.end = arena.len();
        return;
    }
    let mut combined = arena[span.start..span.end].to_vec();
    combined.extend_from_slice(extra);
    span.start = arena.len();
    arena.extend_from_slice(&combined);
    span.end = arena.len();
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

fn apply_pending(visible: &mut Vec<FileSpan>, pending: &[JournalOperation], arena: &mut Vec<u8>) {
    for operation in pending {
        match operation {
            JournalOperation::Put(entry) => apply_put(visible, entry.clone(), arena),
            JournalOperation::Delete(filename) => {
                if let Some(index) = visible.iter().position(|entry| entry.filename == *filename) {
                    visible.remove(index);
                }
            }
        }
    }
}

fn apply_put(visible: &mut Vec<FileSpan>, entry: ZpaqEntry, arena: &mut Vec<u8>) {
    if let Some(index) = visible
        .iter()
        .position(|existing| existing.filename == entry.filename)
    {
        visible.remove(index);
    }
    let start = arena.len();
    arena.extend_from_slice(&entry.data);
    visible.push(FileSpan {
        filename: entry.filename,
        comment: entry.comment,
        start,
        end: arena.len(),
    });
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
    fn test_decode_bounded_limits_total_output() {
        let mut enc = ZpaqEncoder::new(2);
        enc.add_file("a.txt", b"aaa");
        enc.add_file("b.txt", b"bbb");
        let archive = enc.finish().unwrap();
        let entries = decode_bounded(&archive, 6).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            decode_bounded(&archive, 5),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_bounded(&archive, 0).unwrap().len(), 2);
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
    fn test_decode_merges_continuation_segment() {
        // Segments with an empty filename continue the previous file
        // (spec section 8); their payload is appended and their own
        // comment is discarded.
        let mut enc = ZpaqEncoder::new(2);
        enc.add_file("a.txt", b"aaa");
        enc.add_entry(b"", b"ignored", b"bbb");
        enc.add_file("c.txt", b"ccc");
        enc.add_entry(b"", b"", b"ddd");
        let archive = enc.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename_utf8(), Some("a.txt"));
        assert_eq!(entries[0].comment, b"");
        assert_eq!(entries[0].data, b"aaabbb");
        assert_eq!(entries[1].filename_utf8(), Some("c.txt"));
        assert_eq!(entries[1].data, b"cccddd");
    }

    #[test]
    fn test_decode_leading_empty_filename_is_standalone() {
        // An empty filename on the first segment means "no file name is
        // specified", not a continuation, so it stays its own entry.
        let mut enc = ZpaqEncoder::new(2);
        enc.add_entry(b"", b"", b"anon");
        enc.add_file("b.txt", b"bbb");
        let archive = enc.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename, b"");
        assert_eq!(entries[0].data, b"anon");
        assert_eq!(entries[1].filename_utf8(), Some("b.txt"));
        assert_eq!(entries[1].data, b"bbb");
    }

    #[test]
    fn test_decode_bounded_merges_continuation_segment() {
        let mut enc = ZpaqEncoder::new(2);
        enc.add_file("a.txt", b"aaa");
        enc.add_entry(b"", b"", b"bbb");
        let archive = enc.finish().unwrap();

        let entries = decode_bounded(&archive, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename_utf8(), Some("a.txt"));
        assert_eq!(entries[0].data, b"aaabbb");
    }

    #[test]
    fn test_decode_journal_versions_merges_continuation_segment() {
        // Non-journal archives decoded through the journal path apply
        // the same continuation rule as `decode`.
        let mut enc = ZpaqEncoder::new(2);
        enc.add_file("a.txt", b"aaa");
        enc.add_entry(b"", b"", b"bbb");
        let archive = enc.finish().unwrap();

        let versions = decode_journal_versions(&archive).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].entries.len(), 1);
        assert_eq!(versions[0].entries[0].data, b"aaa");
        assert_eq!(versions[1].entries.len(), 1);
        assert_eq!(versions[1].entries[0].filename_utf8(), Some("a.txt"));
        assert_eq!(versions[1].entries[0].data, b"aaabbb");

        let latest = decode_journal_latest(&archive).unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].filename_utf8(), Some("a.txt"));
        assert_eq!(latest[0].data, b"aaabbb");
    }

    #[test]
    fn test_decode_journal_continuation_after_later_file_keeps_older_bytes() {
        // `b.txt` sits after `a.txt` in the arena. Deleting `b.txt` and
        // then continuing `a.txt` must copy `a.txt` forward. The earlier
        // snapshots still name the original range.
        let mut enc = ZpaqEncoder::new(1);
        enc.add_file("a.txt", b"aaa");
        enc.add_file("b.txt", b"bbb");
        let mut archive = enc.finish().unwrap();

        let mut delete = ZpaqJournalEncoder::new(1);
        delete.delete_file("b.txt");
        archive = delete.append_transaction(&archive).unwrap();

        let mut continued = ZpaqEncoder::new(1);
        continued.add_entry(b"", b"", b"ccc");
        archive.extend_from_slice(&continued.finish().unwrap());

        let versions = decode_journal_versions(&archive).unwrap();
        assert_eq!(versions.len(), 4);
        assert_eq!(versions[0].entries[0].data, b"aaa");
        assert_eq!(versions[1].entries[0].data, b"aaa");
        assert_eq!(versions[1].entries[1].data, b"bbb");
        assert_eq!(versions[2].entries.len(), 1);
        assert_eq!(versions[2].entries[0].data, b"aaa");
        assert_eq!(versions[3].entries[0].filename_utf8(), Some("a.txt"));
        assert_eq!(versions[3].entries[0].data, b"aaaccc");
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
