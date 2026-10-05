# romfs

| 項目 | 内容 |
|------|------|
| 形式概要 | Linux 向け read-only ファイルシステムイメージ。`-rom1fs-` スーパーブロック + 16B アラインのファイルヘッダチェーン。圧縮なし |
| 基準仕様 | Linux kernel `Documentation/filesystems/romfs.rst` (`docs/spec/sources/romfs.rst` にスナップショット)、`fs/romfs/` の参照実装の動作 (checksum 規則・exec ビット) |
| 参照実装 | Linux kernel `fs/romfs/` (GPL-2.0、checksum 規則・exec ビットの動作参照)、genromfs 0.5.2 (GPL-2.0+、fixture `tests/fixtures/romfs/genromfs.romfs` 生成 + `fsck.romfs` encoder oracle)。詳細: THIRD_PARTY_NOTICES romfs 項 |
| 実装 | `archive::archive::romfs::{decode, encode::{RomfsEncoder, encode}}` (read/write)。`romfs` feature 配下 |

## スーパーブロック層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | magic `-rom1fs-` (offset 0, 8B) 検証 | romfs.rst File System Layout | ✅ | `rejects_bad_magic_and_checksum` |
| 2 | 全フィールド big-endian 32bit | romfs.rst 「big endian byte order」 | ✅ | 全テスト |
| 3 | `size` フィールド (offset 8) ≤ 入力長 | romfs.rst full size 項目 | ✅ | `test_romfs_rejects_truncated_image` |
| 4 | スーパーブロック checksum (offset 12): 先頭 min(512, size) バイトの longword 合計が 0 になるよう格納 | romfs.rst checksum 項目 + genromfs/kernel の挙動 | ✅ | `test_romfs_rejects_corrupt_checksum` |
| 5 | ボリューム名: offset 16 から NUL 終端、16B アライン | romfs.rst volume name 項目 | ✅ | fixture `testvol` |

## ファイルヘッダ層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 6 | 各ヘッダは 16B アライン、先頭 16B が next/spec/size/checksum | romfs.rst File headers 節 | ✅ | 全テスト |
| 7 | `next` 上位 28 bit = 次 sibling の絶対オフセット、下位 3 bit = 型、bit 3 = exec | romfs.rst next file header 項目 | ✅ | `decodes_genromfs_fixture` (exec.sh) |
| 8 | 型コード: 0 hard link / 1 dir / 2 reg / 3 symlink / 4 block / 5 char / 6 socket / 7 fifo | romfs.rst 型一覧 | ✅ | `RomfsKind` 全バリアント |
| 9 | メタデータ checksum (offset 12): ヘッダ 16B + NUL 終端名 + 16B パディングの合計が 0 | romfs.rst checksum 項目 | ✅ | parse_hdr 内検証 (fixture で網羅) |
| 10 | ファイル名: NUL 終端、未終端は拒否 | romfs.rst file name 項目 | ✅ | `parse_hdr` 内エラー |
| 11 | dir の `spec.info` = 先頭子ヘッダのオフセット、兄弟は `next` で連鎖 | romfs.rst directory 項目 | ✅ | `decodes_flat_and_nested` |
| 12 | hard link の `spec.info` = リンク先ヘッダのオフセット、データはリンク先から解決 | romfs.rst hard link 項目 + fs/romfs inode 扱い | ✅ | fixture `hardlink.txt` |
| 13 | symlink のデータ領域 = リンク先パス文字列 | romfs.rst symbolic link 項目 | ✅ | fixture `symlink` |
| 14 | `.` / `..` 補助エントリはユーザー項目として公開しない | genromfs の出力構造 | ✅ | `test_romfs_genromfs_image_layout` |
| 15 | エントリ名はルートからのフルパス (`/` 区切り) で返す | crate の ArchiveEntry 規約 | ✅ | 全テスト |
| 16 | exec ビット → mode `S_IFMT|0o444 (+0o111)` (kernel romfs_modemap 相当) | fs/romfs 参照動作 | ✅ | fixture `exec.sh`/`hello.txt` |

## 防御的検証

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 17 | ヘッダチェーンの循環を拒否 | 防御的検証 (仕様外) | ✅ | `rejects_header_cycle_and_oob` |
| 18 | イメージ範囲外のヘッダポインタを拒否 | 防御的検証 | ✅ | `rejects_header_cycle_and_oob` |
| 19 | 非アラインヘッダ・イメージサイズ未満の入力を拒否 | 防御的検証 | ✅ | `parse_hdr` / decode 冒頭 |
| 20 | ディレクトリ深さ制限 (128) | 防御的検証 | ✅ | walk 深度ガード |
| 22 | block/char のデバイス番号解釈 | romfs.rst (spec.info) | ✅ | `RomfsEntry::dev: Option<(u16, u16)>` で major/minor を公開する (socket/fifo は None)。`exposes_device_major_minor`, `socket_fifo_have_no_device` |
| 21 | romfs write | romfs.rst + genromfs 出力 | ✅ | `RomfsEncoder`/`encode()` で image 生成 (big-endian header+file headers、directory/symlink/hardlink/device node、volume name)。`roundtrip_basic`, `roundtrip_nested_dirs`, `roundtrip_hardlink_and_devices` |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 23 | owner/permission/timestamp | ❌ n/a | フォーマットにフィールドが存在しない (exec ビットのみ mode に反映) |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 22 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 1 (n/a) |
| **合計** | **23** |
