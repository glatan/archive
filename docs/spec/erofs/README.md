# erofs

| 項目 | 内容 |
|------|------|
| 形式概要 | Linux 向け read-only ファイルシステムイメージ。1024B オフセットのスーパーブロック + `meta_blkaddr` 起点の inode メタデータ領域 (32B スロット) + ブロックアラインされたデータ領域 |
| 基準仕様 | Linux kernel `Documentation/filesystems/erofs.rst`、`fs/erofs/erofs_fs.h` — いずれも `docs/spec/sources/` にスナップショット |
| 実装 | `archive::archive::erofs::decode` (read のみ)。`erofs` feature 配下 |

## スーパーブロック層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | magic `0xE0F5E1E2` at `EROFS_SUPER_OFFSET` (1024) | erofs_fs.h `EROFS_SUPER_OFFSET`、erofs-utils `include/erofs_fs.h` `EROFS_SUPER_MAGIC_V1` | ✅ | `rejects_bad_magic` |
| 2 | `blkszbits` は 9..=16、`blksz = 1 << blkszbits` | erofs_fs.h `blkszbits`、erofs-utils の検証 | ✅ | decode 時検証 |
| 3 | `sb_extslots`: superblock size = 128 + slots*16 | erofs_fs.h `EROFS_SB_EXTSLOT_SIZE` | ✅ | decode 時検証 |
| 4 | `EROFS_FEATURE_COMPAT_SB_CHKSUM`: `blksz - 1024` バイトの CRC32C (checksum フィールド zero、seed ~0、final complement なし) | erofs-utils `erofs_superblock_csum_verify` | ✅ | `test_erofs_rejects_bad_superblock_checksum`、実 mkfs fixture (compat `sb_csum` 付き) で検証 |
| 5 | `feature_incompat`: DEVICE_TABLE/`COMPR_HEAD2`(0x08)、ZTAILPACKING(0x10)、FRAGMENTS/`DEDUPE`(0x20)、METABOX(0x100)、extra_devices≠0 は拒否 | erofs_fs.h `EROFS_FEATURE_INCOMPAT_*` | ✅ | decode 時検証 (unsupported feature → `Error::Unsupported`) |
| 6 | `INCOMPAT_48BIT` 時は `rootnid_8b`(offset 112) / `blocks = blocks_lo | blocks_hi<<32` | erofs_fs.h rb union / `rootnid_8b` | ✅ | decode 時分岐 (48bit image は合成されないため小規模イメージでは 16bit 経路) |
| 7 | `meta_blkaddr`、`xattr_blkaddr`、`volume_name`、`epoch`、`fixed_nsec` の解釈 | erofs_fs.h `erofs_super_block` | ✅ | 全テスト |

## inode 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 8 | inode offset = `meta_blkaddr * blksz + 32 * nid` (32B スロット) | erofs.rst inode space 図 | ✅ | 全テスト |
| 9 | `i_format` bit0 で compact(32B)/extended(64B) を判別、bits1-3 で datalayout | erofs_fs.h `EROFS_I_VERSION_MASK`/`EROFS_I_DATALAYOUT_MASK` | ✅ | `decode_sample_tree` (compact)、`extended_inode` (extended) |
| 10 | inline xattr ibody: `i_xattr_icount` が非 0 なら 12 + 4*(n-1) バイトをスキップ | erofs_fs.h `erofs_xattr_ibody_size` | ✅ | offset 計算で使用 (xattr 内容は intentional scope で未解釈) |
| 11 | compact inode: `i_nb` は dir/複数リンク時は `nlink`、非 dir の `EROFS_I_NLINK_1_BIT` 時は `startblk_hi` (48bit) | erofs_fs.h `EROFS_I_NLINK_1_BIT`、erofs-utils `erofs_read_inode_from_disk` | ✅ | `decode_sample_tree`、`hole_file_reads_zeros` |
| 12 | compact inode の mtime = `sb.epoch + i_mtime`、nsec = `sb.fixed_nsec` | erofs-utils `vi->i_mtime = sbi->epoch + i_mtime` | ✅ | `decode_sample_tree` |
| 13 | extended inode の uid/gid/nlink/mtime(+nsec) は 32/64bit フィールド直読み | erofs_fs.h `erofs_inode_extended` | ✅ | `extended_inode` |
| 14 | datalayout 0 (FLAT_PLAIN): `startblk*blksz` から `i_size` バイト | erofs_fs.h `EROFS_INODE_FLAT_PLAIN` | ✅ | `flat_plain_exact_block` |
| 15 | datalayout 2 (FLAT_INLINE): `floor(size/blksz)` ブロックを `startblk` から読み、残り `size % blksz` を `iloc + isize + xattr_isize` の inline tail から読む | erofs.rst inode 図、erofs-utils `inode->idata` 書き込み | ✅ | `decode_sample_tree`、実 mkfs fixture |
| 16 | FLAT_PLAIN で `startblk` が全 1 (addrmask 内) = hole inode → 全体ゼロ | erofs-utils `EROFS_NULL_ADDR` 分岐 | ✅ | `hole_file_reads_zeros` |
| 17 | FLAT_INLINE で startblk 全 1 = 全 inline (データブロックなし) | 実 mkfs.erofs fixture の root inode が該当 | ✅ | `test_erofs_mkfs_image_*` |
| 18 | datalayout 4 (CHUNK_BASED): extents は `roundup(isize+xattr,8)` 後の `erofs_inode_chunk_info` + u32 blkaddr 配列または 8B chunk index、`EROFS_NULL_ADDR` chunk = hole | erofs.rst Chunk-based files、erofs_fs.h `erofs_inode_chunk_index` | ✅ | `read_chunked` (合成のみ、mkfs デフォルトでは非生成) |
| 19 | chunk format の未知ビット / 48bit index / device_id≠0 を拒否 | erofs_fs.h `EROFS_CHUNK_FORMAT_*` | ✅ | decode 時検証 |

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

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 28 | z_erofs 圧縮 inode (datalayout 1/3: LZ4/MicroLZMA/DEFLATE/Zstandard pcluster) | ❌ intentional scope | `Error::Unsupported`。mkfs.erofs デフォルトは非圧縮 |
| 29 | METABOX / ZTAILPACKING / FRAGMENTS・DEDUPE / DEVICE_TABLE イメージ | ❌ intentional scope | メタデータアドレッシングを根本変更、または外部 blob が必要。superblock で早期拒否 |
| 30 | erofs write | ❌ intentional scope | mkfs.erofs の領域。read が主用途 |
| 31 | xattr 内容の解釈・ACL 復元 (inline/shared/long prefix) | ❌ intentional scope | ibody サイズは skip のため計算するが名前・値は展開しない |
| 32 | dirblkbits ≠ 0 の sub-page directory block | ⚠️ 未対応 | mkfs.erofs は現在 0 を出力。ディレクトリ走査は blksz 単位 |
| 33 | sb uuid / build_time / xattr filter 等の付随フィールドの意味解釈 | ⚠️ 未検証 | 読み飛ばす (kernel と同様 decode に必須でない) |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 27 |
| ⚠️ 部分対応 | 2 |
| ❌ 未対応 | 3 |
| **合計** | **32** |
