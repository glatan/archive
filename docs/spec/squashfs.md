# squashfs (SquashFS image)

| 項目 | 内容 |
|------|------|
| 基準仕様 | SquashFS binary format documentation (dr-emann.github.io/squashfs、SquashFS 4.0) |
| 形式概要 | 96B superblock + metadata block 列 (inode/dir table) + lookup table (fragment/ID を実読み、export/xattr は境界計算のみ) + data block |
| 実装範囲 | **read のみ** (write は intentional scope 外) |

参照: <https://dr-emann.github.io/squashfs/squashfs.html>

### superblock / metadata 基盤

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | 96B superblock: magic `hsqs` (0x73717368)、version 4.0、block_size 4KiB〜1MiB の 2 冪で block_log と一致 | §3 | ✅ | `rejects_bad_magic`, `rejects_bad_version`, `rejects_bad_block_size` |
| 2 | 全整数 little-endian | §2 | ✅ | `le16`/`le32`/`le64` |
| 3 | metadata block: 16bit header (下位15bit=on-disk size、MSB=非圧縮) + 8KiB 上限 | §2.2 | ✅ | `read_metadata_block` |
| 4 | metadata 参照 `disk_pos << 16 \| inner_offset` (disk_pos は table 先頭相対) | §2.2 | ✅ | `MetaRun::resolve` |
| 5 | lookup table: 非圧縮 u64 location 列 + metadata block 化された固定長 entry 列 | §2.3 | ✅ | `read_lookup_table` (fragment / ID table) |
| 6 | compressor option block (flag 0x0400) は読み飛ばし (decode に不要) | §3.1 | ✅ | 明示的 skip |

### compressor

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | ID 1 gzip = raw zlib stream → `compress::zlib` | §2.4 | ✅ | `test_squashfs_decode_mksquashfs_image` (gzip) |
| 8 | ID 4 xz = LZMA2/xz stream (CRC32) → `compress::xz` | §2.4 | ✅ | 同上 (xz) |
| 9 | ID 5 lz4 = raw LZ4 block → `compress::lz4` | §2.4 | ✅ | 同上 (lz4) |
| 10 | ID 6 zstd → `compress::zstd` | §2.4 | ✅ | 同上 (zstd) |
| 11 | ID 3 lzo = LZO1X raw → `compress::lzo` | §2.4 | ✅ | 同上 (lzo) |
| 12 | ID 2 lzma (LZMA1, deprecated) は `Unsupported` | §2.4 | ⚠️ | upstream で deprecated のため非対応を明示 |
| 13 | 圧縮が入力を超える場合の非圧縮格納 (data block bit24 / metadata MSB) | §2.1/§2.2 | ✅ | `parses_compressed_metadata_and_data` ほか |
| 14 | metadata/data block の伸張上限 (8KiB / block_size) を強制 | §2.1/§2.2 | ✅ | bounded decompress |

### inode / ディレクトリ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | common inode header (type/mode/uid_idx/gid_idx/mtime/inode_number) | §5.1 | ✅ | `InodeHeader::parse` |
| 16 | basic/extended directory inode → dir table 参照 (listing size = file_size - 3) | §5.2 | ⚠️ | `parses_subdir_symlink` (basic のみ検証。extended 分岐は実装済み・未テスト) |
| 17 | basic/extended file inode → block sizes 配列 + fragment 参照 | §5.3 | ⚠️ | `parses_basic_image` (basic のみ検証。extended 分岐は実装済み・未テスト) |
| 18 | basic/extended symlink inode → target path | §5.4 | ⚠️ | `parses_subdir_symlink` (basic のみ検証。extended 分岐は実装済み・未テスト) |
| 19 | device / IPC inode (basic + extended) を受理 | §5.5/§5.6 | ⚠️ | `InodeBody::Device`/`Ipc` 分岐実装済み (テストなし) |
| 20 | dir table: header (count-1 / start / base inode) + entry (offset / s16 diff / basic type / name_size-1 / name) | §6 | ✅ | `read_dir_listing` |
| 21 | data block: bit24 = 非圧縮、size 0 = sparse zero block | §4 | ✅ | `read_data_block` |
| 22 | fragment tail: frag table entry (start/size/unused) + frag_offset | §4/§7 | ✅ | `parses_fragment_tail` |
| 23 | UID/GID は ID table 経由で解決 | §9 | ✅ | `lookup_id` |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 24 | `mksquashfs` 生成 image (gzip/zstd/xz/lz4/lzo) の decode | system interop | ✅ | `test_squashfs_decode_mksquashfs_image` (mksquashfs 不在環境では実質 skip) |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 25 | magic `hsqs` で自動検出 | CLI detection | ✅ | `detect_squashfs` |
| 26 | `archive extract` は regular file を展開 | CLI semantics | ✅ | `extract.rs` の `Format::Squashfs` アーム |
| 27 | fuzz algorithm `squashfs` (self-regression 含む) | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 28 | `.squashfs` write (encoder) | — | ❌ | read-only scope (intentional) |
| 29 | LZMA1 (compressor id 2) payload の伸張 | §2.4 | ❌ | upstream deprecated。`Unsupported` を返す (intentional) |
| 30 | xattr / export table の展開 | §8/§10 | ❌ | メタデータ解析は layout 検証まで。xattr 値の公開は intentional scope 外 |
| 31 | filesystem セマンティクス (デバイス node 作成、パーミッション適用) | — | ❌ | 抽出は name/content 列挙まで (intentional) |
