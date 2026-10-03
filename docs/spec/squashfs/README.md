# squashfs (SquashFS image)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [SquashFS binary format documentation](https://dr-emann.github.io/squashfs/squashfs.html) (SquashFS 4.0、コミュニティ逆解析文書 = de facto 仕様、ローカルスナップショット: `docs/spec/sources/squashfs_4.0.html`) |
| 形式概要 | 96B superblock + metadata block 列 (inode/dir table) + lookup table (fragment/ID/xattr を実読み、export は境界計算のみ) + data block |
| 実装範囲 | read + write (write は SquashFS 4.0 / regular file + symlink + device/IPC + directory tree、任意で fragment table・複数 UID/GID・export table・xattr table・directory index (ext dir inode)・sparse block 自動検出) |

参照: <https://dr-emann.github.io/squashfs/squashfs.html>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| SquashFS 4.0 | [SquashFS binary format doc](https://dr-emann.github.io/squashfs/squashfs.html) | ✅ | ✅ | write は files+dirs の最小 subset |
| compressor gzip / xz / lz4 / zstd / lzo | [SquashFS binary format doc](https://dr-emann.github.io/squashfs/squashfs.html) | ✅ | ✅ | 各 compressor module へディスパッチ |
| compressor lzma1 | [SquashFS binary format doc](https://dr-emann.github.io/squashfs/squashfs.html) | ❌ | ❌ | `Unsupported` |

mksquashfs 生成イメージの decode、`unsquashfs` による本 writer 出力の展開はテストで確認済み。

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
| 13 | 圧縮が入力を超える場合の非圧縮格納 (data block bit24 / metadata MSB) | §2.1/§2.2 | ✅ | `parses_compressed_metadata_and_data` ほか |
| 14 | metadata/data block の伸張上限 (8KiB / block_size) を強制 | §2.1/§2.2 | ✅ | bounded decompress |

### write

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | SquashFS 4.0 superblock emit: mkfs_time、inode_count、bytes_used、各 table offset、compressor id、flags (no-frag/no-xattr/duplicates) | §3 | ✅ | `single_file_roundtrip` ほか encode.rs unit tests |
| 16a | compressor options block: LZ4 選択時は superblock 直後に非圧縮 metadata block (u32 version=1 + u32 flags) を emit、COMP_OPT flag を立てる (LZ4 は必須) | §3.1 | ✅ | `test_squashfs_encoder_unsquashfs_extract` (lz4) |
| 16 | data block: block_size 単位で分割、compressor で圧縮・非圧縮 fallback (bit24)、非 sparse (size 0 出力なし、empty file は block なし) | §4 | ✅ | `multi_block_file`, `empty_file_and_empty_dir` |
| 17 | inode table: basic dir inode + basic file inode (blocks_start/file_size が u32 を超える場合は extended file inode 9)。inode は metadata block をまたがない (8KiB 境界で pad) | §5 | ✅ | `inodes_do_not_straddle_metablock` |
| 18 | inode table は非圧縮格納 (dir inode patch 後も on-disk offset が不変であることを保証するため)。dir table は compressor で圧縮 | §2.2 | ✅ | `compressors_roundtrip` |
| 19 | dir table: header (count-1 / start_block=inode chunk disk pos / base inode) + entry (offset / s16 diff / type / name_size-1 / name)。子 inode を連番化して diff を i16 に収める | §6 | ✅ | `nested_dirs_roundtrip` |
| 20 | fragment table: `with_fragments()` で file tail を共有 fragment block に格納し 16B entry 表 + location list を emit (未使用時は tail を block 格納・TABLE_ABSENT)。export table は `with_export_table()`、xattr は `*_xattrs` API で emit 可 | §7/§8/§10 | ✅ | `fragments_roundtrip`, `fragments_disabled_by_default`, `single_file_roundtrip` |
| 20a | basic symlink inode (type 3) の emit: nlink + target bytes、dir listing type 3 | §5.4 | ✅ | `symlink_roundtrip`, `test_squashfs_encoder_symlink_fragments_ids` (`add_symlink`/`add_symlink_owned`) |
| 21 | ID table: 複数 UID/GID (`add_file_owned`/`add_symlink_owned` で初出順に dedup 追加、inode は uid_idx/gid_idx で参照)。uid=gid=0 のみなら 1 entry | §9 | ✅ | `multiple_ids_roundtrip`, `symlink_roundtrip` |
| 22 | パス正規化: `/` 区切りの中間 dir を自動生成。空要素 `.` `..` 重複名を `InvalidData` で拒否 | crate-local | ✅ | `rejects_bad_paths_and_compressor` |
| 23 | 全 compressor (gzip/xz/lz4/zstd/lzo) で encode→decode roundtrip + `unsquashfs` 実展開 | system interop | ✅ | `compressors_roundtrip`, `test_squashfs_encoder_unsquashfs_extract` |
| 23a | write: device/IPC inode emit — `add_block_device`/`add_char_device` (rdev = new_encode_dev)、`add_fifo`/`add_socket` (basic inode 4-7、dir listing type 一致) | §5.5/§5.6 | ✅ | `device_and_ipc_inodes_roundtrip`, `test_squashfs_encoder_extended_unsquashfs` (unsquashfs が device node 実体化) |
| 23b | write: sparse block — all-zero data block は block_sizes 0 で格納 (data なし) | §4 | ✅ | `sparse_blocks_roundtrip` |
| 23c | write: export table — `with_export_table()` で inode_number-1 → u64 inode ref の lookup table emit | §8 | ✅ | `export_table_roundtrip` (superblock offset + decode) |
| 23d | write: xattr table — `add_file_xattrs`/`add_symlink_xattrs` で kv metadata run + 16B lookup entries + {kv_start,count,locations} header emit、inode は ext type (xattr idx)。prefix は user./trusted./security. のみ、値は inline のみ | §10 | ✅ | `xattrs_roundtrip`, `rejects_bad_xattr_name` |
| 23e | write: directory index — `with_dir_index()` で非空 dir を ext dir inode + §6.1 index (header 毎の {index,start,name}) として emit。run plan は fixpoint で収束 | §6.1/§5.2 | ✅ | `dir_index_roundtrip` |
| 23f | write: dir header は inode diff が i16 超過・256 entries 到達でも新 header で split | §6 | ✅ | run 分割ロジック (fixpoint) |

### inode / ディレクトリ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 24 | common inode header (type/mode/uid_idx/gid_idx/mtime/inode_number) | §5.1 | ✅ | `InodeHeader::parse` |
| 25 | basic/extended directory inode → dir table 参照 (listing size = file_size - 3) | §5.2 | ✅ | `parses_subdir_symlink`, `parses_extended_dir_inode` |
| 26 | basic/extended file inode → block sizes 配列 + fragment 参照 | §5.3 | ✅ | `parses_basic_image`, `parses_extended_file_inode` (実装の 4B オフセットずれを修正済み) |
| 27 | basic/extended symlink inode → target path | §5.4 | ✅ | `parses_subdir_symlink`, `parses_extended_symlink_inode` |
| 28 | device / IPC inode (basic + extended) を受理 | §5.5/§5.6 | ✅ | `parses_device_and_ipc_inodes` |
| 29 | dir table: header (count-1 / start / base inode) + entry (offset / s16 diff / basic type / name_size-1 / name) | §6 | ✅ | `read_dir_listing` |
| 30 | data block: bit24 = 非圧縮、size 0 = sparse zero block | §4 | ✅ | `read_data_block` |
| 31 | fragment tail: frag table entry (start/size/unused) + frag_offset | §4/§7 | ✅ | `parses_fragment_tail` |
| 32 | UID/GID は ID table 経由で解決 | §9 | ✅ | `lookup_id` |
| 39 | xattr table (id table + lookup + key/value ブロック) の展開、`SquashfsEntry::xattrs` 公開 | §10 | ✅ | inline/out-of-line value、prefix (user./trusted./security.) を解決。lookup `size` は stat 用論理サイズ (upstream `get_xattr_id`) のため count 駆動で parse。`parses_xattr_table`, `rejects_bad_xattrs` |
| 41 | directory index (拡張 dir inode の index_count 分の {index,start,name}) の read、`SquashfsEntry::dir_index` 公開 | §6.1 | ✅ | `parses_dir_index`, `rejects_truncated_dir_index`, `test_squashfs_decode_xattrs_and_dir_index` |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 33 | `mksquashfs` 生成 image (gzip/zstd/xz/lz4/lzo) の decode / 本 writer 出力の `unsquashfs` 展開 | system interop | ✅ | `test_squashfs_decode_mksquashfs_image`, `test_squashfs_encoder_unsquashfs_extract` (ツール不在環境では実質 skip) |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 34 | magic `hsqs` で自動検出 | CLI detection | ✅ | `detect_squashfs` |
| 35 | `archive extract` は regular file を展開 | CLI semantics | ✅ | `extract.rs` の `Format::Squashfs` アーム |
| 36 | fuzz algorithm `squashfs` (self-regression 含む) | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 38 | LZMA1 (compressor id 2) payload の伸張 | §2.4 | ❌ | upstream deprecated。`compressor_dispatch` で `Unsupported` を返す (intentional) |
| 40 | filesystem セマンティクス (デバイス node 作成、パーミッション適用) | crate-local | ❌ | 抽出は name/content 列挙まで (intentional) |
