# erofs

| 項目 | 内容 |
|------|------|
| 形式概要 | Linux 向け read-only ファイルシステムイメージ。1024B オフセットのスーパーブロック + `meta_blkaddr` 起点の inode メタデータ領域 (32B スロット) + ブロックアラインされたデータ領域 |
| 基準仕様 | Linux kernel `Documentation/filesystems/erofs.rst` + **canonical on-disk 定義** erofs-utils `include/erofs_fs.h` (MIT、userspace 正本) — いずれも `docs/spec/sources/` にスナップショット。kernel `fs/erofs/erofs_fs.h` も MIT SPDX で pin 済み (`Z_EROFS_LI_HOLE` は kernel 版のみに存在するため併用)。以下 `erofs_fs.h` 引用は erofs-utils `include/erofs_fs.h` を指す |
| 参照実装 | erofs-utils `mkfs.erofs`/`fsck.erofs` (GPL-2.0+、fixture 生成・交差検証・encoder 出力検証 oracle + encoder layout の behavioral reference)。個別 kernel .c (super.c/inode.c/data.c/zmap.c、`docs/spec/sources/` に pin) は metabox・chunk map 等の動作確認のみに使用 (コード取り込みなし)。詳細: THIRD_PARTY_NOTICES erofs 項 |
| 実装 | `archive::archive::erofs::{decode, encode::ErofsEncoder, ErofsArchiveEncoder}` (read/write。write は非圧縮 flat layout のみ)。`erofs` feature 配下 |

## スーパーブロック層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | magic `0xE0F5E1E2` at `EROFS_SUPER_OFFSET` (1024) | erofs_fs.h `EROFS_SUPER_OFFSET`、erofs-utils `include/erofs_fs.h` `EROFS_SUPER_MAGIC_V1` | ✅ | `rejects_bad_magic` |
| 2 | `blkszbits` は 9..=16、`blksz = 1 << blkszbits` | erofs_fs.h `blkszbits`、erofs-utils の検証 | ✅ | decode 時検証。ただし `blksz < 1024 + sb_size` は別途 reject するため実効範囲は 11..=16 (kernel は 9 以上を受理するが本実装は厳格側) |
| 3 | `sb_extslots`: superblock size = 128 + slots*16 | erofs_fs.h `EROFS_SB_EXTSLOT_SIZE` | ✅ | decode 時検証 |
| 4 | `EROFS_FEATURE_COMPAT_SB_CHKSUM`: `blksz - 1024` バイトの CRC32C (checksum フィールド zero、seed ~0、final complement なし) | erofs-utils `erofs_superblock_csum_verify` | ✅ | `test_erofs_rejects_bad_superblock_checksum`、`rejects_short_image_with_sb_checksum` (checksum 領域の EOF 境界)、実 mkfs fixture (compat `sb_csum` 付き) で検証 |
| 5 | `feature_incompat`: 受理側は LZ4_0PADDING(0x01)/COMPR_CFGS(0x02)/CHUNKED_FILE(0x04)/COMPR_HEAD2(0x08)/ZTAILPACKING(0x10)/FRAGMENTS・DEDUPE(0x20)/XATTR_PREFIXES(0x40)/48BIT(0x80)/METABOX(0x100)。拒否は `extra_devices≠0` のみ。未知 incompat ビットは kernel (`~ALL_FEATURE_INCOMPAT` reject) と異なり黙許する (lenient) | erofs_fs.h `EROFS_FEATURE_INCOMPAT_*` | ✅ | decode 時検証 (extra_devices → `Error::Unsupported`) |
| 6 | `INCOMPAT_48BIT` 時は `rootnid_8b`(offset 112) / `blocks = blocks_lo | blocks_hi<<32` | erofs_fs.h rb union / `rootnid_8b` | ✅ | `decodes_48bit_rootnid`。`rootnid_8b==0` の場合は 16bit `rootnid_2b` に fallback (kernel と同一条件) |
| 7 | `meta_blkaddr`、`xattr_blkaddr`、`volume_name`、`epoch`、`fixed_nsec` の解釈 | erofs_fs.h `erofs_super_block` | ✅ | 全テスト |
| 33 | sb uuid / build_time / xattr filter 等の付随フィールドの意味解釈 | erofs_fs.h `erofs_super_block` | ✅ | `ErofsImage.superblock` (`ErofsSuperblock`: feature_compat/incompat, inos, blocks, meta/xattr_blkaddr, uuid, epoch, fixed_nsec, build_time, xattr_prefix_count/start, packed_nid, ishare_xattr_prefix_id) + COMPAT_* const 公開。xattr filter 本体は lookup 加速用途のみで解釈不要。`superblock_metadata_fields`, `test_erofs_mkfs_image_superblock` |
| 35 | COMPR_CFGS (`available_compr_algs` + 4-aligned len+data レコード列): 未知 alg bit (`algs & !0xF`) reject、LZMA dict_size 4096..8MiB、DEFLATE windowbits<=15、Zstandard format/windowlog、len=0 -> 65536 | erofs_fs.h `erofs_sb_info.u1` / `erofs_algorithm`、erofs-utils `z_erofs_parse_cfgs` | ✅ | `set_compr_cfgs` 経由の `compressed_*` テスト群で検証 |

## inode 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 28 | z_erofs 圧縮 inode (datalayout 1/3: LZ4/MicroLZMA/DEFLATE/Zstandard pcluster) | erofs.rst "Data compression"、kernel `fs/erofs/erofs_fs.h` `z_erofs_*`/`Z_EROFS_*` | ✅ | `z.rs` の `read_compressed` が mapheader + noncompact/compact index + extent レコードを decode (HEAD1/HEAD2/NONHEAD/PLAIN・HOLE (`Z_EROFS_LI_HOLE`)・partial-ref・big pcluster・`ADVISE_INTERLACED_PCLUSTER` raw extent)。`compressed_*` / `rejects_*` 各テスト + mkfs.erofs 実 fixture (integration 6 件)。packed inode・fragment・tail-packing は #29 の intentional |
| 8 | inode offset = `meta_blkaddr * blksz + 32 * nid` (32B スロット) | erofs.rst inode space 図 | ✅ | 全テスト |
| 9 | `i_format` bit0 で compact(32B)/extended(64B) を判別、bits1-3 で datalayout | erofs_fs.h `EROFS_I_VERSION_MASK`/`EROFS_I_DATALAYOUT_MASK` | ✅ | `decode_sample_tree` (compact)、`extended_inode` (extended) |
| 10 | inline xattr ibody: `i_xattr_icount` が非 0 なら 12 + 4*(n-1) バイトをスキップ | erofs_fs.h `erofs_xattr_ibody_size` | ✅ | offset 計算で使用 (xattr 内容の解釈は #31) |
| 11 | compact inode: `i_nb` は dir/複数リンク時は `nlink`、非 dir の `EROFS_I_NLINK_1_BIT` 時は `startblk_hi` (48bit) | erofs_fs.h `EROFS_I_NLINK_1_BIT`、erofs-utils `erofs_read_inode_from_disk` | ✅ | `decode_sample_tree`、`hole_file_reads_zeros` |
| 12 | compact inode の mtime = `sb.epoch + i_mtime`、nsec = `sb.fixed_nsec` | erofs-utils `vi->i_mtime = sbi->epoch + i_mtime` | ✅ | `decode_sample_tree` |
| 13 | extended inode の uid/gid/nlink/mtime(+nsec) は 32/64bit フィールド直読み | erofs_fs.h `erofs_inode_extended` | ✅ | `extended_inode` |
| 14 | datalayout 0 (FLAT_PLAIN): `startblk*blksz` から `i_size` バイト | erofs_fs.h `EROFS_INODE_FLAT_PLAIN` | ✅ | `flat_plain_exact_block` |
| 15 | datalayout 2 (FLAT_INLINE): `floor(size/blksz)` ブロックを `startblk` から読み、残り `size % blksz` を `iloc + isize + xattr_isize` の inline tail から読む | erofs.rst inode 図、erofs-utils `inode->idata` 書き込み | ✅ | `decode_sample_tree`、実 mkfs fixture |
| 16 | FLAT_PLAIN で `startblk` が全 1 (addrmask 内) = hole inode → 全体ゼロ | erofs-utils `EROFS_NULL_ADDR` 分岐 | ✅ | `hole_file_reads_zeros` |
| 17 | FLAT_INLINE で startblk 全 1 = 全 inline (データブロックなし) | 実 mkfs.erofs fixture の root inode が該当 | ✅ | `test_erofs_mkfs_image_*` |
| 18 | datalayout 4 (CHUNK_BASED): chunk array (u32 blkaddr 配列または 8B `erofs_inode_chunk_index`) は `ALIGN(iloc + inode_isize + xattr_isize, unit)` (unit=4 or 8) に配置され、先行する chunk_info レコードは存在しない (format は inode `i_u` union)。`EROFS_NULL_ADDR` (addrmask 内全 1) chunk = hole | erofs.rst Chunk-based files、erofs_fs.h `erofs_inode_chunk_index`、kernel `erofs_map_chunks` | ✅ | `decodes_chunked_inode_block_map`, `decodes_chunked_inode_index_with_hole` (合成、mkfs デフォルトでは非生成)。offset 計算の `+4` ずれを修正済み |
| 19 | chunk format の未知ビット / 48bit index / device_id≠0 を拒否 | erofs_fs.h `EROFS_CHUNK_FORMAT_*` | ✅ | `rejects_chunked_unknown_format_bits` (未知ビット)、48bit index・device_id≠0 は decode 時検証 |
| 29a | METABOX (0x100) の metabox inode decode | erofs_fs.h `EROFS_FEATURE_INCOMPAT_METABOX` | ✅ | `metabox_nid` が指す metabox inode の blob を decode し、dirent nid bit63 付き inode のメタデータと `COMPAT_SHARED_EA_IN_METABOX` の共有 xattr を metabox 空間で解決。`metabox_inode_decodes`, `metabox_shared_xattr`, `rejects_metabox_*` 等 |
| 36 | datalayout 5-7 (reserved) を `Error::Unsupported` で拒否 | erofs_fs.h `EROFS_INODE_*` enum | ✅ | decode 時検証 |

## dirent 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 20 | directory data は `erofs_dirent` (12B: nid u64, nameoff u16, file_type u8, reserved u8) の配列 + name 領域 | erofs.rst Directories 節、erofs_fs.h `erofs_dirent` | ✅ | 全テスト |
| 21 | `de[0].nameoff` = 最初の名前のオフセット = dirent 領域の終端 | erofs.rst nameoff0 記述 | ✅ | `rejects_name_oob` |
| 22 | 名前は `nameoff` から次の nameoff / ブロック末尾まで (末尾 NUL パディング許容) | erofs.rst "trailing '\0'" | ✅ | `decode_sample_tree` |
| 23 | `.` / `..` エントリは出力に含めない | 実 mkfs fixture で確認 | ✅ | `test_erofs_mkfs_image_layout` |
| 24 | dirent `nid` の bit63 (METABOX ビット) はマスク | erofs_fs.h `EROFS_DIRENT_NID_METABOX_BIT` | ✅ | decode 時マスク |
| 25 | kind は dirent `file_type` でなく inode `i_mode` の S_IFMT で決定 (dir/reg/lnk/その他) | POSIX mode ビット | ✅ | kind enum 全バリアント |
| 26 | ディレクトリ循環・自己参照・過剰ネスト (深さ 64) を拒否 | 防御的検証 | ✅ | `rejects_dir_cycle` |
| 27 | inode/data/name への全ポインタの範囲検査 | 防御的検証 | ✅ | `rejects_truncated`、`rejects_name_oob`、`test_erofs_rejects_truncation` |
| 32 | `dirblkbits ≠ 0` の sub-page directory block: dir file を `1<<dirblkbits` 単位で再分割して走査 | erofs_fs.h `dirblkbits` (sb offset 90) | ✅ | 非ゼロ時は sub-page 分割、不正値は `InvalidData`。`dirblksz_subpage_directory`, `rejects_dirblkbits_out_of_range` |
| 34 | z_erofs tail-packing: `Z_EROFS_ADVISE_INLINE_PCLUSTER` (ZTAILPACKING feature) の inline 末尾データ、`ADVISE_FRAGMENT_PCLUSTER` / `FRAGMENT_INODE_BIT` (FRAGMENTS feature) の packed inode 参照 | erofs_fs.h `z_erofs_map_header` union (`h_idata_size`/`h_fragmentoff`)、erofs.rst | ✅ | feature bit 未設定の wire マーカーは reject。mkfs.erofs `-Eztailpacking`/`-Efragments` fixture 4 件。`ztailpacking_inline_*`, `fragment_*`, `test_erofs_ztailpacking`, `test_erofs_fragments`, `test_erofs_all_fragments`, `test_erofs_ztailpacking_fragments` |
| 31 | xattr 解釈 (inline/shared/long prefix) | erofs_fs.h `erofs_xattr_ibody_header`/`erofs_xattr_entry`/`erofs_xattr_long_prefix`、erofs.rst | ✅ | `ErofsEntry::xattrs: Vec<ErofsXattr>`。inline entry + shared xattr (xattr_blkaddr 経由) + long prefix (xattr_prefix_start)。metabox 内の shared/long prefix は metabox 空間で解決 (#29a)。`xattr_inline_entries`, `xattr_shared_entry`, `rejects_*xattr*` |
| 30 | erofs write | erofs_fs.h | ✅ | `ErofsEncoder`/`ErofsArchiveEncoder` で非圧縮 flat layout image を生成 (compact/extended inode、INLINE/PLAIN tail、superblock CRC32C、uid/gid/mode)。xattr/ACL、z_erofs 圧縮・chunk・fragment・metabox・multi-device、special file (device/fifo/socket/hardlink) の出力は encoder の scope 外。`roundtrip_*` 各テスト + `test_erofs_encode_fsck_extract` (fsck.erofs oracle)。fuzz harness `erofs` で roundtrip + corrupt 対象 |
| 37 | `COMPAT_PLAIN_XATTR_PFX` (0x10): xattr prefix テーブルを plain 領域 (prefix_start) から解決 | erofs_fs.h `EROFS_FEATURE_COMPAT_XATTR_PREFIXES` | ✅ | decode 時分岐 |
| 38 | `EROFS_I_DOT_OMITTED_BIT` (dirent `i_format` bit4): `.` エントリ省略の示唆 | erofs_fs.h | ✅ | 実装は常に名前比較で `.`/`..` を skip するため本ビットは no-op (読み替え不要) |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 29 | DEVICE_TABLE (`extra_devices != 0`) / DEDUPE (0x20) | ❌ intentional scope | DEVICE_TABLE は外部 blob 参照で単一 `&[u8]` 入力モデルと不整合のため `Error::Unsupported`。DEDUPE は feature フラグのみで wire 上の固有構造を持たない (`erofs_fs.h` に定義なし、dedup 済み chunk index は既存 chunked decode がそのまま処理)。METABOX の対応は #29a |


## 実装メモ

- dirent 名は `ErofsEntry.name: String` のため非 UTF-8 名を含む画像は全体を reject する (kernel/mkfs は任意バイト列を許容 — strict 側の差分)。
- flat / chunked / compressed のいずれの配置でも、データ読み取り前に `i_size` 分のバッファを事前確保する。`decode_bounded` は各 inode の宣言 `i_size` を出力上限 `max_output` の残量から事前に差し引き、上限を超過した場合は割り当て前に `Error::OutputLimitExceeded` で拒否する。この上限計算には通常ファイルだけでなく、ディレクトリ、packed inode、metabox の各ペイロードも含まれる。一方、無制限の `decode` では入力データ長や `blocks` との整合性を事前に照合しないため、細工された巨大な `i_size` によってメモリ割り当て失敗を引き起こす可能性がある。
- 残存リスク: 圧縮 inode における DEFLATE および Zstandard の pcluster 展開は、全量をメモリへ展開した後に要求長へ切り詰める方式を採っている。そのため、展開処理の途中でライブラリが一時確保するメモリは、`decode_bounded` による事前検査では制限できない（対照的に LZ4 と MicroLZMA はデコーダに出力上限を指定できるため、展開中のメモリ割り当ても制限される）。ただし、この過剰割り当てを引き起こすには整合した圧縮メタデータを備えた画像構造が必要であり、正常なエンコード出力をランダムに変異させるファジングでは該当コードパスに到達しにくい。
- FLAT_INLINE の inline tail 読み取りは kernel の「inline data は同一 meta block 内」の制約を検査しない (lenient。z.rs 側の `emit_inline` は検査済みで非対称)。
- 圧縮 pcluster は画像末尾で clamp される (kernel は plen 分の I/O を要求 — lenient)。NONHEAD の delta 値は CBLKCNT 以外参照しない。

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 38 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 1 (intentional scope) |
| **合計** | **39** |
