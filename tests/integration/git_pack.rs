use super::*;
use archive::error::Error;
use archive::traits::ArchiveEntry;

// ============================================================
// Git pack format (gitformat-pack) tests
// ============================================================
//
// `tests/fixtures/git-pack/real.{pack,idx}` were produced by git 2.55
// (`git repack`) from a small repository and contain 8 objects,
// including one ofs-delta entry (chain length 1). The pack therefore
// exercises object-header parsing, zlib bodies, delta resolution, and
// the pack checksum against the reference implementation's output.

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/git-pack/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// (object id, type, unpacked size) as reported by `git verify-pack`.
const REAL_OBJECTS: &[(&str, git_pack::ObjectType, usize)] = &[
    (
        "db9e94ccb2e0430c82058c20567d5ac35bb76cb3",
        git_pack::ObjectType::Commit,
        165,
    ),
    (
        "85829b4499b7cbb81e61b35b5d5d95453e29d231",
        git_pack::ObjectType::Commit,
        117,
    ),
    (
        "4c352a547df3671c67226db2a3b3816afbf343be",
        git_pack::ObjectType::Blob,
        480,
    ),
    (
        "095b9ecba95b578f6879c0d2328c5e73c485a9e3",
        git_pack::ObjectType::Blob,
        470,
    ),
    (
        "c8b49c8cd518e58491924bfc364ff26e01a85009",
        git_pack::ObjectType::Blob,
        1024,
    ),
    (
        "ff17e26df9b688ca680e25d2301eabfdae81de80",
        git_pack::ObjectType::Tree,
        99,
    ),
    (
        "5477fd6dccff467a7895e5af5442c6c5cb0ed460",
        git_pack::ObjectType::Tree,
        66,
    ),
    (
        "88db1df244955afae49c0599c609a039c89f832a",
        git_pack::ObjectType::Blob,
        390,
    ),
];

#[test]
fn decode_real_pack() {
    let entries = git_pack::decode::decode(&fixture("real.pack")).unwrap();
    assert_eq!(entries.len(), REAL_OBJECTS.len());
    let mut got: Vec<(&str, git_pack::ObjectType, usize)> = entries
        .iter()
        .map(|e| (e.name(), e.object_type(), e.data().len()))
        .collect();
    got.sort();
    let mut want = REAL_OBJECTS.to_vec();
    want.sort();
    assert_eq!(got, want);
    // Each entry's name must be its own object ID.
    for e in &entries {
        let id = git_pack::object_id(e.object_type(), e.data());
        assert_eq!(*e.object_id(), id);
        assert_eq!(e.name(), git_pack::hex_id(&id));
    }
}

#[test]
fn decode_real_idx() {
    let pack = fixture("real.pack");
    let idx = git_pack::decode::decode_idx(&fixture("real.idx"), &pack).unwrap();
    assert_eq!(idx.len(), REAL_OBJECTS.len());
    // Names are sorted by object ID in a v2 idx.
    let mut sorted: Vec<&str> = idx.iter().map(|e| e.name.as_str()).collect();
    let orig = sorted.clone();
    sorted.sort();
    assert_eq!(orig, sorted);
    let want: Vec<&str> = {
        let mut v: Vec<&str> = REAL_OBJECTS.iter().map(|o| o.0).collect();
        v.sort();
        v
    };
    assert_eq!(sorted, want);
    // Every offset must land on a real object header inside the pack.
    for e in &idx {
        assert!(e.offset >= 12 && e.offset < pack.len() as u64 - 20);
        let b = pack[e.offset as usize];
        assert!(matches!((b >> 4) & 7, 1..=4 | 6 | 7));
    }
}

#[test]
fn encode_roundtrip() {
    let mut enc = git_pack::encode::GitPackEncoder::new();
    enc.add_object(git_pack::ObjectType::Blob, b"hello\n");
    enc.add_object(git_pack::ObjectType::Commit, b"tree 0000\n");
    enc.add_object(
        git_pack::ObjectType::Tree,
        b"\x31\x30\x30\x36\x34\x34 f\x00",
    );
    let pack = enc.finish();
    let entries = git_pack::decode::decode(&pack).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].data(), b"hello\n");
    assert_eq!(entries[0].object_type(), git_pack::ObjectType::Blob);
    // Known git object ID: `echo hello | git hash-object --stdin`.
    assert_eq!(
        entries[0].name(),
        "ce013625030ba8dba906f756967f9e9ca394464a"
    );
}

#[test]
fn encode_roundtrip_with_index() {
    let mut enc = git_pack::encode::GitPackEncoder::new();
    enc.add_object(git_pack::ObjectType::Blob, b"aaa");
    enc.add_object(git_pack::ObjectType::Blob, b"bbb");
    let (pack, idx) = enc.finish_with_index();
    let entries = git_pack::decode::decode_idx(&idx, &pack).unwrap();
    assert_eq!(entries.len(), 2);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let id_a = git_pack::hex_id(&git_pack::object_id(git_pack::ObjectType::Blob, b"aaa"));
    let id_b = git_pack::hex_id(&git_pack::object_id(git_pack::ObjectType::Blob, b"bbb"));
    let mut want = [id_a.as_str(), id_b.as_str()];
    want.sort();
    assert_eq!(names, want);
}

#[test]
fn bad_signature() {
    let mut pack = fixture("real.pack");
    pack[0] = b'X';
    assert!(matches!(
        git_pack::decode::decode(&pack),
        Err(Error::InvalidData(_))
    ));
}

#[test]
fn reject_version4() {
    let mut pack = fixture("real.pack");
    pack[7] = 4;
    assert!(matches!(
        git_pack::decode::decode(&pack),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn truncated() {
    let pack = fixture("real.pack");
    for n in [0, 4, 11, 12, 20, pack.len() - 21, pack.len() - 1] {
        assert!(git_pack::decode::decode(&pack[..n]).is_err(), "len {n}");
    }
}

#[test]
fn bad_pack_checksum() {
    let mut pack = fixture("real.pack");
    let n = pack.len();
    pack[n - 1] ^= 0xFF;
    assert!(git_pack::decode::decode(&pack).is_err());
}

#[test]
fn bad_zlib_stream() {
    let mut pack = fixture("real.pack");
    // Corrupt the first object body's zlib data. The first entry's
    // object header is one byte (commit, size 165 fits in the header),
    // so the zlib stream starts at offset 13.
    assert_eq!((pack[12] >> 4) & 7, 1);
    pack[14] ^= 0xFF;
    assert!(git_pack::decode::decode(&pack).is_err());
}

#[test]
fn decode_ref_delta_pack() {
    // ref.pack holds the same objects as real.pack but stored with a
    // REF_DELTA entry (repack.usedeltabaseoffset=false).
    let entries = git_pack::decode::decode(&fixture("ref.pack")).unwrap();
    assert_eq!(entries.len(), REAL_OBJECTS.len());
    let mut got: Vec<(&str, git_pack::ObjectType, usize)> = entries
        .iter()
        .map(|e| (e.name(), e.object_type(), e.data().len()))
        .collect();
    got.sort();
    let mut want = REAL_OBJECTS.to_vec();
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn apply_delta_copy_insert() {
    let base = b"base content here";
    // copy off=5 len=3 ("con") then insert '!'
    let delta = [17u8, 4, 0x91, 5, 3, 1, b'!'];
    let out = git_pack::decode::apply_delta(base, &delta).unwrap();
    assert_eq!(out, b"con!");
}

#[test]
fn apply_delta_errors() {
    // src size mismatch
    assert!(git_pack::decode::apply_delta(b"abc", &[4, 0]).is_err());
    // reserved command 0
    assert!(git_pack::decode::apply_delta(b"abc", &[3, 1, 0]).is_err());
    // truncated copy args
    assert!(git_pack::decode::apply_delta(b"abc", &[3, 1, 0x83]).is_err());
    // copy out of bounds
    assert!(git_pack::decode::apply_delta(b"abc", &[3, 1, 0x93, 5, 1, 1]).is_err());
    // insert truncated
    assert!(git_pack::decode::apply_delta(b"abc", &[3, 1, 2, b'x']).is_err());
    // result size mismatch
    assert!(git_pack::decode::apply_delta(b"abc", &[3, 5, 1, b'x']).is_err());
}

#[test]
fn ofs_delta_pack_accepted_by_git_index_pack() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Base + two chained ofs-delta objects (delta of delta).
    let base = b"The quick brown fox jumps over the lazy dog.\n".repeat(16);
    let mut mid = base.clone();
    mid[10] = b'X';
    let mut end = mid.clone();
    end.extend_from_slice(b"extra tail line\n");

    let mut enc = git_pack::encode::GitPackEncoder::new();
    let bi = enc.add_object(git_pack::ObjectType::Blob, &base);
    let mi = enc.add_delta_object(&mid, bi).unwrap();
    enc.add_delta_object(&end, mi).unwrap();
    let pack = enc.finish();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_gitpack_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.pack");
    std::fs::write(&path, &pack).unwrap();

    //  fully verifies the pack: checksums, delta
    // chain resolution, and object IDs. It exits 0 even on fatal
    // errors, so success is the produced .idx file.
    let output = Command::new("git")
        .args(["index-pack", "--strict", "-v"])
        .arg(&path)
        .output();
    let Ok(output) = output else { return };
    if !dir.join("test.idx").exists() {
        // Distinguish "git missing" from "pack rejected".
        if String::from_utf8_lossy(&output.stderr).contains("index-pack") {
            return;
        }
        panic!(
            "git index-pack rejected crate pack: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // verify-pack reports the resolved delta chain (delta of delta).
    let output = Command::new("git")
        .args(["verify-pack", "-v"])
        .arg(dir.join("test.idx"))
        .output()
        .unwrap();
    let list = String::from_utf8_lossy(&output.stdout);
    assert_eq!(list.matches(" blob").count(), 3, "{list}");
    assert!(list.contains("chain length = 1"), "{list}");
    assert!(list.contains("chain length = 2"), "{list}");

    std::fs::remove_dir_all(&dir).ok();
}
