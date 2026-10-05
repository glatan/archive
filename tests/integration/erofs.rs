use super::*;

// ============================================================
// erofs integration tests (mkfs.erofs fixture interop)
// ============================================================

/// Reference image produced by upstream erofs-utils `mkfs.erofs`
/// (committed at `tests/fixtures/erofs/mkfs.erofs.img`; erofs-utils
/// is not packaged in the test container). Source tree:
/// `hello.txt` ("hello erofs world\n"), `big.txt` (3000 x 'A'),
/// `subdir/one.dat` ("x"), `subdir/deep/two.dat` ("y"),
/// `link.txt` -> "hello.txt". Verified extractable by upstream
/// `fsck.erofs --extract`.
const FIXTURE: &[u8] = include_bytes!("../fixtures/erofs/mkfs.erofs.img");

fn find<'a>(img: &'a erofs::decode::ErofsImage, path: &str) -> &'a erofs::decode::ErofsEntry {
    img.entries
        .iter()
        .find(|e| e.name == path)
        .unwrap_or_else(|| panic!("missing entry {path}"))
}

#[test]
fn test_erofs_mkfs_image_layout() {
    let img = erofs::decode::decode(FIXTURE).unwrap();
    assert_eq!(img.block_size, 4096);
    assert!(img.entries.iter().all(|e| e.name != "." && e.name != ".."));
    let mut names: Vec<&str> = img.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "big.txt",
            "hello.txt",
            "link.txt",
            "subdir",
            "subdir/deep",
            "subdir/deep/two.dat",
            "subdir/one.dat"
        ]
    );
}

#[test]
fn test_erofs_mkfs_image_contents() {
    let img = erofs::decode::decode(FIXTURE).unwrap();

    let hello = find(&img, "hello.txt");
    assert_eq!(hello.kind, erofs::decode::ErofsKind::File);
    assert_eq!(hello.data, b"hello erofs world\n");

    // 3000 bytes < 4 KiB block: fully-inline tail data.
    let big = find(&img, "big.txt");
    assert_eq!(big.data.len(), 3000);
    assert!(big.data.iter().all(|&b| b == b'A'));

    assert_eq!(
        find(&img, "subdir").kind,
        erofs::decode::ErofsKind::Directory
    );
    assert_eq!(
        find(&img, "subdir/deep").kind,
        erofs::decode::ErofsKind::Directory
    );
    assert_eq!(find(&img, "subdir/one.dat").data, b"x");
    assert_eq!(find(&img, "subdir/deep/two.dat").data, b"y");

    let link = find(&img, "link.txt");
    assert_eq!(link.kind, erofs::decode::ErofsKind::Symlink);
    assert_eq!(link.data, b"hello.txt");
}

#[test]
fn test_erofs_mkfs_image_superblock() {
    // Superblock metadata exposed via `ErofsImage::superblock`;
    // values match the on-disk layout verified against erofs_fs.h
    // (this image sets COMPAT_SB_CHKSUM | COMPAT_MTIME, no volume
    // label or uuid, metadata at block 0).
    let img = erofs::decode::decode(FIXTURE).unwrap();
    let sb = &img.superblock;
    assert_eq!(
        sb.feature_compat,
        erofs::decode::COMPAT_SB_CHKSUM | erofs::decode::COMPAT_MTIME
    );
    assert_eq!(sb.feature_incompat, 0);
    assert_eq!(sb.inos, 8);
    assert_eq!(sb.blocks, img.blocks);
    assert_eq!(sb.meta_blkaddr, 0);
    assert_eq!(sb.xattr_blkaddr, 0);
    assert_eq!(sb.uuid, [0u8; 16]);
    assert_eq!(sb.epoch, 0);
    assert_eq!(sb.fixed_nsec, 0);
    assert_eq!(sb.build_time, 0);
    assert_eq!(sb.xattr_prefix_count, 0);
    assert_eq!(sb.xattr_prefix_start, 0);
    assert_eq!(sb.packed_nid, 0);
    assert_eq!(sb.ishare_xattr_prefix_id, 0);
}

#[test]
fn test_erofs_codec_trait() {
    let codec = erofs::ErofsCodec;
    use archive::traits::{ArchiveDecode, ArchiveEntry};
    let entries = codec.decode(FIXTURE).unwrap();
    assert!(entries.iter().any(|e| e.name() == "hello.txt"));
}

#[test]
fn test_erofs_rejects_truncation() {
    // Cut inside referenced file data; decode must fail rather than
    // silently emit partial entries.
    let truncated = &FIXTURE[..5000];
    assert!(erofs::decode::decode(truncated).is_err());
}

#[test]
fn test_erofs_rejects_bad_superblock_checksum() {
    // The committed image sets EROFS_FEATURE_COMPAT_SB_CHKSUM;
    // corrupting an in-scope superblock byte must trip the CRC32C
    // verification.
    let mut bad = FIXTURE.to_vec();
    bad[1024 + 40] ^= 0xff; // meta_blkaddr
    assert!(matches!(
        erofs::decode::decode(&bad),
        Err(archive::error::Error::ChecksumMismatch { .. })
            | Err(archive::error::Error::InvalidData(_))
            | Err(archive::error::Error::UnexpectedEof)
    ));
}

#[test]
fn test_erofs_fsck_extract_matches_decode() {
    use std::process::Command;

    // Optional upstream interop: when fsck.erofs is available, its
    // extracted tree must match our decoded entries.
    if Command::new("fsck.erofs")
        .arg("--help")
        .output()
        .map(|o| !o.status.success() && o.stderr.is_empty())
        .unwrap_or(true)
    {
        eprintln!("fsck.erofs not available; skipping");
        return;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_erofs_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let img_path = dir.join("test.erofs");
    std::fs::write(&img_path, FIXTURE).unwrap();
    let ext = dir.join("ext");
    let out = Command::new("fsck.erofs")
        .arg(format!("--extract={}", ext.display()))
        .arg(&img_path)
        .output()
        .expect("fsck.erofs");
    assert!(
        out.status.success(),
        "fsck.erofs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let img = erofs::decode::decode(FIXTURE).unwrap();
    for e in &img.entries {
        match e.kind {
            erofs::decode::ErofsKind::File => {
                let disk = std::fs::read(ext.join(&e.name)).unwrap();
                assert_eq!(disk, e.data, "file {} mismatch", e.name);
            }
            erofs::decode::ErofsKind::Symlink => {
                let target = std::fs::read_link(ext.join(&e.name)).unwrap();
                assert_eq!(
                    target.as_os_str().as_encoded_bytes(),
                    &e.data[..],
                    "symlink {} mismatch",
                    e.name
                );
            }
            erofs::decode::ErofsKind::Directory => {
                assert!(ext.join(&e.name).is_dir(), "missing dir {}", e.name);
            }
            _ => {}
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================
// compressed (z_erofs) images produced by upstream mkfs.erofs
// (erofs-utils 1.9.4). Source tree: hello.txt
// ("hello compressed erofs\n") and big.txt (135000 bytes of a
// repeating 45-byte pattern). Each fixture exercises a different
// on-disk variant.
// ============================================================

/// mkfs.erofs -zlz4hc : compacted-2B compact indexes + LZ4.
const FIXTURE_LZ4HC: &[u8] = include_bytes!("../fixtures/erofs/mkfs.lz4hc.img");
/// mkfs.erofs -zlz4hc -C8192 : big pclusters (CBLKCNT nonheads).
const FIXTURE_LZ4_BIG: &[u8] = include_bytes!("../fixtures/erofs/mkfs.lz4-bigpcluster.img");
/// mkfs.erofs -zlz4 -Elegacy-compress : noncompact 8-byte indexes.
const FIXTURE_LZ4_FULL: &[u8] = include_bytes!("../fixtures/erofs/mkfs.lz4-full-idx.img");
/// mkfs.erofs -zlz4hc -E48bit : z_erofs_extent record layout.
const FIXTURE_LZ4_EXT: &[u8] = include_bytes!("../fixtures/erofs/mkfs.lz4-extents.img");
/// mkfs.erofs -zlzma : MicroLZMA with a compression-config record.
#[cfg(any(
    feature = "lzma-alone",
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip"
))]
const FIXTURE_MICROLZMA: &[u8] = include_bytes!("../fixtures/erofs/mkfs.microlzma.img");
/// mkfs.erofs -zlz4hc:lzma : per-pcluster HEAD1/HEAD2 algorithm
/// selection across two algorithms.
#[cfg(any(
    feature = "lzma-alone",
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip"
))]
const FIXTURE_MULTI: &[u8] = include_bytes!("../fixtures/erofs/mkfs.lz4hc-microlzma.img");

fn big_txt_expected() -> Vec<u8> {
    b"the quick brown fox jumps over the lazy dog. "
        .iter()
        .cycle()
        .take(45 * 3000)
        .copied()
        .collect()
}

fn check_compressed_fixture(img: &[u8], label: &str) {
    let d = erofs::decode::decode(img).unwrap_or_else(|e| panic!("{label}: {e}"));
    let big = find(&d, "big.txt");
    assert_eq!(big.data, big_txt_expected(), "{label}: big.txt mismatch");
    assert_eq!(
        find(&d, "hello.txt").data,
        b"hello compressed erofs\n",
        "{label}: hello.txt mismatch"
    );
}

#[test]
fn test_erofs_compressed_lz4hc_compact() {
    check_compressed_fixture(FIXTURE_LZ4HC, "lz4hc-compact");
}

#[test]
fn test_erofs_compressed_lz4_bigpcluster() {
    check_compressed_fixture(FIXTURE_LZ4_BIG, "lz4-bigpcluster");
}

#[test]
fn test_erofs_compressed_lz4_full_index() {
    check_compressed_fixture(FIXTURE_LZ4_FULL, "lz4-full-index");
}

#[test]
fn test_erofs_compressed_lz4_extents() {
    check_compressed_fixture(FIXTURE_LZ4_EXT, "lz4-extents");
}

#[cfg(any(
    feature = "lzma-alone",
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip"
))]
#[test]
fn test_erofs_compressed_microlzma() {
    check_compressed_fixture(FIXTURE_MICROLZMA, "microlzma");
}

#[cfg(any(
    feature = "lzma-alone",
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip"
))]
#[test]
fn test_erofs_compressed_multi_algorithm() {
    check_compressed_fixture(FIXTURE_MULTI, "lz4hc+microlzma");
}

// ============================================================
// ztailpacking / fragments / xattr images produced by upstream
// mkfs.erofs (erofs-utils 1.9.4). Common source tree:
//   big.txt  = "The quick brown fox jumps over the lazy dog. " x3200
//              (user.comment="fixture hello xattr", user.rating="7")
//   small.txt= "small file content for tail packing\n" x37
//   tiny.txt = "tiny frag\n" (user.empty="")
//   mid.bin  = bytes i % 251 for 4173 (security.selinux="system_u:object_r:test_t:s0")
//   sub/nested.txt = "nested " x200 (user.tag="nestedxattr")
//   link.txt -> "big.txt"
// ============================================================

/// mkfs.erofs -zlz4 -Eztailpacking : inline tail-packing (COMPACT).
const FIXTURE_ZTAILPACKING: &[u8] = include_bytes!("../fixtures/erofs/mkfs.ztailpacking.img");
/// mkfs.erofs -zlz4 -Efragments : packed-inode fragment tails (FULL).
const FIXTURE_FRAGMENTS: &[u8] = include_bytes!("../fixtures/erofs/mkfs.fragments.img");
/// mkfs.erofs -zlz4 -Eall-fragments : whole-file packed-inode records.
const FIXTURE_ALLFRAGMENTS: &[u8] = include_bytes!("../fixtures/erofs/mkfs.all-fragments.img");
/// mkfs.erofs -zlz4 -Eztailpacking,fragments : combined feature set.
const FIXTURE_TAILFRAG: &[u8] = include_bytes!("../fixtures/erofs/mkfs.tailfrag.img");

fn check_fixture_tree(img: &erofs::decode::ErofsImage) {
    let big = find(img, "big.txt");
    assert_eq!(big.kind, erofs::decode::ErofsKind::File);
    assert_eq!(big.data.len(), 144000);
    let chunk = b"The quick brown fox jumps over the lazy dog. ";
    let want: Vec<u8> = chunk.repeat(3200);
    assert_eq!(big.data, want);

    let small = find(img, "small.txt");
    assert_eq!(small.data.len(), 36 * 37);
    assert!(
        small
            .data
            .starts_with(b"small file content for tail packing\n")
    );

    assert_eq!(find(img, "tiny.txt").data, b"tiny frag\n");
    assert_eq!(find(img, "mid.bin").data.len(), 4173);
    assert_eq!(find(img, "sub/nested.txt").data.len(), 200 * 7);
    assert_eq!(find(img, "link.txt").data, b"big.txt");
}

fn xattr<'a>(e: &'a erofs::decode::ErofsEntry, name: &str) -> Option<&'a [u8]> {
    e.xattrs
        .iter()
        .find(|x| x.name == name)
        .map(|x| x.value.as_slice())
}

fn check_fixture_xattrs(img: &erofs::decode::ErofsImage) {
    let big = find(img, "big.txt");
    assert_eq!(big.xattrs.len(), 2);
    assert_eq!(
        xattr(big, "user.comment"),
        Some(b"fixture hello xattr".as_slice())
    );
    assert_eq!(xattr(big, "user.rating"), Some(b"7".as_slice()));
    let mid = find(img, "mid.bin");
    assert_eq!(
        xattr(mid, "security.selinux"),
        Some(b"system_u:object_r:test_t:s0".as_slice())
    );
    assert_eq!(
        xattr(find(img, "tiny.txt"), "user.empty"),
        Some(b"".as_slice())
    );
    assert_eq!(
        xattr(find(img, "sub/nested.txt"), "user.tag"),
        Some(b"nestedxattr".as_slice())
    );
}

#[test]
fn test_erofs_ztailpacking() {
    let img = erofs::decode::decode(FIXTURE_ZTAILPACKING).unwrap();
    assert_eq!(img.superblock.packed_nid, 0);
    check_fixture_tree(&img);
    check_fixture_xattrs(&img);
}

#[test]
fn test_erofs_fragments() {
    let img = erofs::decode::decode(FIXTURE_FRAGMENTS).unwrap();
    assert_ne!(img.superblock.packed_nid, 0);
    check_fixture_tree(&img);
    check_fixture_xattrs(&img);
}

#[test]
fn test_erofs_all_fragments() {
    // Every file data block lives inside the packed inode
    // (Z_EROFS_FRAGMENT_INODE_BIT on each compressed inode).
    let img = erofs::decode::decode(FIXTURE_ALLFRAGMENTS).unwrap();
    assert_ne!(img.superblock.packed_nid, 0);
    check_fixture_tree(&img);
    check_fixture_xattrs(&img);
}

#[test]
fn test_erofs_ztailpacking_fragments() {
    let img = erofs::decode::decode(FIXTURE_TAILFRAG).unwrap();
    assert_ne!(img.superblock.packed_nid, 0);
    check_fixture_tree(&img);
    check_fixture_xattrs(&img);
}

// ============================================================
// erofs encoder tests (ErofsEncoder -> decode roundtrip and
// fsck.erofs extract interop)
// ============================================================

/// Build a small uncompressed image with our encoder.
fn encoded_image() -> Vec<u8> {
    let mut enc = erofs::encode::ErofsEncoder::new();
    enc.set_volume_name("rustfs");
    enc.add_dir("dir1/sub");
    enc.add_file("hello.txt", b"hello erofs encoder");
    enc.add_file("dir1/file.bin", b"nested data");
    enc.add_file("empty.txt", b"");
    let big: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
    enc.add_file("dir1/sub/big.dat", &big);
    enc.add_symlink("alink", "dir1/file.bin");
    enc.finish().unwrap()
}

#[test]
fn test_erofs_encode_decode_roundtrip() {
    let image = encoded_image();
    let img = erofs::decode::decode(&image).unwrap();
    assert_eq!(img.volume_name, "rustfs");
    assert_eq!(img.block_size, 4096);
    // The encoder emits EROFS_FEATURE_COMPAT_SB_CHKSUM by default;
    // decode() already verified the CRC32C at this point.
    assert_ne!(
        img.superblock.feature_compat & erofs::decode::COMPAT_SB_CHKSUM,
        0
    );
    let mut names: Vec<&str> = img.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "alink",
            "dir1",
            "dir1/file.bin",
            "dir1/sub",
            "dir1/sub/big.dat",
            "empty.txt",
            "hello.txt"
        ]
    );
    assert_eq!(find(&img, "hello.txt").data, b"hello erofs encoder");
    assert_eq!(find(&img, "empty.txt").data, b"");
    assert_eq!(
        find(&img, "dir1/sub/big.dat").data,
        (0..9000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>()
    );
    assert_eq!(find(&img, "alink").kind, erofs::decode::ErofsKind::Symlink);
    assert_eq!(find(&img, "alink").data, b"dir1/file.bin");
}

#[test]
fn test_erofs_mkfs_image_reencode_roundtrip() {
    // Decode the committed mkfs.erofs fixture, re-encode every entry
    // with our encoder, and require an identical decoded view.
    let img = erofs::decode::decode(FIXTURE).unwrap();
    let mut enc = erofs::encode::ErofsEncoder::new();
    for e in &img.entries {
        let opts = erofs::encode::ErofsEntryOptions {
            mode: e.mode & 0o7777,
            uid: e.uid,
            gid: e.gid,
            mtime: e.mtime,
            mtime_nsec: e.mtime_nsec,
        };
        match e.kind {
            erofs::decode::ErofsKind::File => {
                enc.add_file_with_options(&e.name, &e.data, &opts);
            }
            erofs::decode::ErofsKind::Directory => {
                enc.add_dir_with_options(&e.name, &opts);
            }
            erofs::decode::ErofsKind::Symlink => {
                enc.add_symlink_with_options(
                    &e.name,
                    core::str::from_utf8(&e.data).unwrap(),
                    &opts,
                );
            }
            _ => {}
        }
    }
    let image2 = enc.finish().unwrap();
    let img2 = erofs::decode::decode(&image2).unwrap();
    assert_eq!(img.entries.len(), img2.entries.len());
    let mut names1: Vec<&str> = img.entries.iter().map(|e| e.name.as_str()).collect();
    let mut names2: Vec<&str> = img2.entries.iter().map(|e| e.name.as_str()).collect();
    names1.sort_unstable();
    names2.sort_unstable();
    assert_eq!(names1, names2);
    for name in names1 {
        let a = find(&img, name);
        let b = find(&img2, name);
        assert_eq!(a.kind, b.kind, "{name}");
        assert_eq!(a.mode, b.mode, "{name}");
        assert_eq!(a.data, b.data, "{name}");
    }
}

#[test]
fn test_erofs_encode_fsck_extract() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Optional upstream interop: the real checker validates the
    // superblock checksum and extracts the whole tree.
    if Command::new("fsck.erofs")
        .arg("--help")
        .output()
        .map(|o| !o.status.success() && o.stderr.is_empty())
        .unwrap_or(true)
    {
        eprintln!("fsck.erofs not available; skipping");
        return;
    }
    let image = encoded_image();
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_erofs_enc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let img_path = dir.join("enc.erofs");
    std::fs::write(&img_path, &image).unwrap();
    let ext = dir.join("ext");
    let out = Command::new("fsck.erofs")
        .arg(format!("--extract={}", ext.display()))
        .arg(&img_path)
        .output()
        .expect("fsck.erofs");
    assert!(
        out.status.success(),
        "fsck.erofs rejected our image: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(ext.join("hello.txt")).unwrap(),
        b"hello erofs encoder"
    );
    assert_eq!(
        std::fs::read(ext.join("dir1/file.bin")).unwrap(),
        b"nested data"
    );
    assert_eq!(std::fs::read(ext.join("empty.txt")).unwrap(), b"");
    assert_eq!(
        std::fs::read(ext.join("dir1/sub/big.dat")).unwrap(),
        (0..9000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>()
    );
    assert_eq!(
        std::fs::read_link(ext.join("alink"))
            .unwrap()
            .as_os_str()
            .as_encoded_bytes(),
        b"dir1/file.bin"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
