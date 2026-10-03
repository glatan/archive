# cramfs

| 項目 | 内容 |
|------|------|
| 形式概要 | Linux 向け小容量 read-only 圧縮ファイルシステム。64B スーパーブロック + 12B inode 配列 (width-first) + ページ単位 zlib 圧縮データブロック |
| 基準仕様 | Linux kernel `Documentation/filesystems/cramfs.rst`、`fs/cramfs/README` (レイアウト)、`include/uapi/linux/cramfs_fs.h` (構造体定義) — いずれも `docs/spec/sources/` にスナップショット |
| 参照実装 | util-linux `mkfs.cramfs`/`fsck.cramfs` (GPL-2.0+、interop oracle)。詳細: THIRD_PARTY_NOTICES cramfs 項 |
| 実装 | `archive::archive::cramfs::decode` (read のみ)。`cramfs` feature 配下 |

## スーパーブロック層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | magic `0x28cd3d45` を offset 0 または 512 (shifted root) で受理 | cramfs_fs.h `CRAMFS_SIGNATURE`、magic ファイル表、fs/cramfs/inode.c の shifted-root 扱い | ✅ | `decodes_shifted_root` |
| 2 | signature `"Compressed ROMFS"` (offset 16, 16B) 検証 | cramfs_fs.h `cramfs_super.signature` | ✅ | `rejects_bad_magic_and_trailing_garbage` |
| 3 | `flags & ~CRAMFS_SUPPORTED_FLAGS` を拒否 | cramfs_fs.h `CRAMFS_SUPPORTED_FLAGS` | ✅ | decode 時検証 (kernel と同じ規則) |
| 4 | `size` フィールド ≤ 入力長、`size >= 76` | cramfs_super.size | ✅ | `rejects_bad_magic_and_trailing_garbage` |
| 5 | root inode (offset 64) は directory 必須 | cramfs_fs.h `cramfs_super.root` | ✅ | decode 時 assert |
| 6 | オフセット/ポインタは 4B 単位 (`offset` field = byte_offset/4) | cramfs_fs.h `cramfs_inode.offset` コメント | ✅ | 全テスト |
| 23 | fsid CRC 検証 | mkcramfs.c (crc32 over `[shift..size)`、fsid.crc フィールドは 0 扱い) | ✅ | `CramfsImage::fsid_crc_ok: Option<bool>` — `CRAMFS_FLAG_FSID_VERSION_2` 時のみ検証し結果を情報として公開 (kernel 同様 reject はしない)。`fsid_crc_verified_as_info`, `test_cramfs_fsid_crc_mismatch_is_informational` |
| 24 | ボリューム名 (superblock offset 48, 16B、ヌル終端/pad) の公開 | cramfs_fs.h `cramfs_super.name` | ✅ | `CramfsImage::name` = `lossy_name(&sb[48..64])`。decode.rs:80-81,348 |

## inode・ディレクトリ層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 7 | inode 12B: mode:16 | uid:16 | size:24 | gid:8 | namelen:6 | offset:26 | cramfs_fs.h `cramfs_inode` | ✅ | 全テスト |
| 8 | ディレクトリは `offset*4` から `size` バイトの連続した子 inode 領域 | fs/cramfs/README `<directory_structure>`、inode.c readdir | ✅ | `decodes_nested_dirs_and_symlink` |
| 9 | 名前は namelen*4 バイト、NUL パディング | cramfs_fs.h namelen コメント | ✅ | 全テスト |
| 10 | S_IFMT: 0x4000 dir / 0x8000 reg / 0xA000 lnk、それ以外は Other として残す | POSIX mode ビット | ✅ | kind enum 全バリアント |
| 11 | 深さ制限 (64) で循環ディレクトリを拒否 | §4.1 相当の防御 | ✅ | walk 深度ガード |
| 12 | hard link なし (mkcramfs は重複内容を別 inode にする) | cramfs.rst Usage Notes | ✅ | format 上 inode は各エントリ固有 |

## データブロック層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 13 | nblocks = ceil(size/4096)、各 u32 ポインタは i 番ブロックの「終端」絶対オフセット、先頭ブロックはポインタ列直後 | fs/cramfs/README `<file_data>` | ✅ | `decodes_multiblock_file` (10000B → 3 ブロック) |
| 14 | ブロックは zlib compress 出力 (ヘッダ+adler あり) | README `<block>` | ✅ | mkfs.cramfs interop で実検証 |
| 15 | ブロックポインタ 0 = hole ブロック → 4096B (末尾では残り分) の NUL 出力 | fs/cramfs/README (cramfs_layout.txt) "Holes" 節 + inode.c readpage | ✅ | `file_data` hole 分岐 (ユニット fixture でカバー) |
| 16 | `CRAMFS_FLAG_EXT_BLOCK_POINTERS`: UNCOMPRESSED(bit31) は生コピー、DIRECT_PTR(bit30) は `ptr<<2` の絶対位置 (uncompressed は blksize、compressed は先頭 2B が長さ) | fs/cramfs/README EXT_BLOCK_POINTERS 節 | ✅ | 実装済み (mkfs.cramfs が発行しないため合成 fixture でテスト) |
| 17 | symlink のデータ = リンク先パス (ファイルと同じブロック形式) | inode.c readpage/コメント | ✅ | `test_cramfs_decode_mkfs_image` (alink) |
| 18 | 空ファイル/空ディレクトリは offset=0, size=0 でデータなし | inode コメント | ✅ | `test_cramfs_decode_mkfs_image` (empty.txt) |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 19 | cramfs write | ❌ intentional scope | mkcramfs の領域。read が主用途 |
| 20 | big-endian image | ❌ intentional scope | kernel 自身が foreign-endian を拒否 (`host-endian format`)。LE image のみ受理 |
| 21 | XIP メモリマップ実行 / MTD 直読み | ❌ intentional scope | `CRAMFS_MTD` はカーネル実装の話。データ展開としては DIRECT_PTR 対応で範囲内 |
| 22 | timestamp/ctime (format に存在しない) | ❌ n/a | cramfs.rst: 全て epoch 扱い |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 20 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 0 |
| **合計** | **24** |
