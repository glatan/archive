# iso9660

| 項目 | 内容 |
|------|------|
| 形式概要 | ISO 9660 (= ECMA-119) CD-ROM ファイルシステムイメージ。System Area + Volume Descriptor 列 + Path Table + ディレクトリレコード木。Rock Ridge (IEEE P1282) と Joliet 補足ボリュームを decode |
| 基準仕様 | ECMA-119 4th ed. (`sources/ecma119.pdf`)、Linux kernel `Documentation/filesystems/isofs.rst` + `include/uapi/linux/iso_fs.h`、SUSP 1.10 (`sources/susp.shar`)、RRIP 1.12 (`sources/rrip112.pdf`)、Joliet spec (`sources/jolspec.html`)、El Torito 1.0 (`sources/eltorito_spec_1.0.pdf`)、zisofs format (`sources/zisofs_format.txt`)、Apple TN FL36 (`sources/apple_iso9660_fl36.html`) — いずれも `docs/spec/sources/` にスナップショット |
| 実装 | `archive::archive::iso9660::decode` (read のみ)。`iso9660` feature 配下 |

## Volume Descriptor 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | Volume Descriptor は sector 16 から連続配置、1 sector = 2048 バイト固定 | ECMA-119 §8.1.3、§7.1 | ✅ | `test_iso9660_plain_image` |
| 2 | 各 VD は type (offset 0) + `"CD001"` + version(1) の 7 バイトヘッダ | ECMA-119 §8.1 | ✅ | `test_iso9660_rejects_corrupt` (magic 破壊) |
| 3 | Primary VD (type 1) 必須・重複は拒否、Boot Record (0) / Supplementary (2) / Partition (3) はスキップ、Terminator (255) で走査終了 | ECMA-119 §8.2–8.5 | ✅ | `test_iso9660_rejects_corrupt` (重複 PVD) |
| 4 | Terminator 未到達 (入力末尾まで VD 列が続く) は `InvalidData` | ECMA-119 §8.1.3 | ✅ | `test_iso9660_rejects_truncated` |
| 5 | VD version byte = 1、それ以外は拒否 | ECMA-119 §8.1 | ✅ | decode 時検証 |
| 6 | PVD フィールド: volume_space_size / logical_block_size の both-endian 一致検証 (§7.3.3/§7.2.3) | ECMA-119 §9.1.2/§9.1.3 | ✅ | decode 時検証 |
| 7 | logical_block_size は 512–32KiB の 2 冪のみ受理 | ECMA-119 §6.2 + 防御的範囲 | ✅ | decode 時検証 |
| 8 | root directory record は PVD 内固定 34 バイト (offset 156) | ECMA-119 §9.1 | ✅ | 全テスト |
| 9 | volume_id は PVD offset 40 の 32 バイト d/a-characters (末尾空白・NUL 除去) | ECMA-119 §9.1.4 | ✅ | `test_iso9660_plain_image` |

## Directory Record 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 10 | record 長 ≥34、name 長、padding byte (name 偶数時)、record は論理ブロックを跨がない (残りはゼロパッド) | ECMA-119 §9.1.1/§9.1.13 | ✅ | `test_iso9660_plain_image`、builder/parse の往復で確認 |
| 11 | extent/size は both-endian (LE+BE 両記述が一致することを検証) | ECMA-119 §7.3.3 | ✅ | `test_iso9660_rejects_corrupt` 内検証 |
| 12 | flags bit1 = directory、それ以外は file | ECMA-119 §9.1.6 | ✅ | `test_iso9660_plain_image` |
| 13 | file unit size / interleave gap ≠ 0 (インターリーブファイル) は `Unsupported` | ECMA-119 §9.1.8/§9.1.9 | ✅ | decode 時検証 |
| 14 | file identifier `\x00` / `\x01` は `.` / `..` で出力しない | ECMA-119 §9.1.10、isofs.rst | ✅ | `test_iso9660_*` (全 fixture で `.`/`..` 非出現を検査) |
| 15 | ISO9660 identifier の `;version` サフィックスと裸の末尾 `.` を除去 | ECMA-119 §9.1.11/§10 | ✅ | `test_iso9660_plain_image` (`HELLO.TXT` 等) |
| 16 | extent 読み出しは `extent + ext_attr_len` ブロック開始、全アクセス範囲検査 | ECMA-119 §9.1.3、防御的検証 | ✅ | `test_iso9660_rejects_truncated` (sector 30 切断) |
| 17 | ディレクトリ循環・深さ >64 を拒否 (extent+size の BTreeSet で検出) | 防御的検証 | ✅ | `rejects_*` / walk guard |
| 18 | 7 バイト directory time (year=1900+, tz 15min 単位) を Unix epoch に変換 | ECMA-119 §9.1.5 | ✅ | civil-from-days (Howard Hinnant) で実装、`test_iso9660_*` |
| 19 | multi-extent file (flags bit7) は `Unsupported` | ECMA-119 §9.1.6 | ✅ | decode 時検証 |

## SUSP / Rock Ridge 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 20 | SUSP 検出: root `.` record の System Use 先頭が `SP` + check bytes `0xBE 0xEF` | SUSP §5.3 | ✅ | `test_iso9660_rockridge_image` (`has_rock_ridge`) |
| 21 | SUSP エントリ共通構造: sig(2) + len(1) + ver(1) + payload、len<4 や残端数は走査終了 | SUSP §4 | ✅ | 全 Rock Ridge テスト |
| 22 | `CE`: (block, offset, length) の both-endian 3 組で継続領域を読み、最深 4 段まで再帰マージ | SUSP §5.1 | ✅ | 実 bsdtar fixture (root NM が CE 越し) で検証 |
| 23 | `ST`: System Use 走査終了 | SUSP §5.5 | ✅ | decode 時処理 |
| 24 | `NM`: alternate name、flags bit0=継続、bit1/2=`.`/`..` を識別、連続 NM を連結 | RRIP §4.1 | ✅ | `test_iso9660_rockridge_image` (lowercase 名) |
| 25 | `PX`: both-endian の mode/nlinks/uid/gid を POSIX メタデータとして採用 | RRIP §4.1.1 (v1.12) | ✅ | `test_iso9660_rockridge_image` (mode 04xxxx / 010xxxx) |
| 26 | `SL`: component (flags,len,content) 列を `/` 結合でリンクターゲット化、bit3=root / bit4,5=volroot,host を処理 | RRIP §4.1.3 | ✅ | `test_iso9660_rockridge_image` (`link.txt -> hello.txt`) |
| 27 | `TF`: timestamp ビット列、7B 形式の modify time (bit1) を mtime として採用。17B 長形式は読み飛ばし | RRIP §4.1.6 | ✅ | decode 時処理 |
| 28 | RRIP 名は Joliet/ISO 名に優先、PX 非存在時は dir=0o040555 / file=0o100444 の合成 mode | 優先順位設計 | ✅ | `test_iso9660_rockridge_image` / `test_iso9660_plain_image` |
| 29 | PX mode の S_IFMT で kind を決定: 0o120000→Symlink、0o100000→File、その他→`Other(sfmt)` | RRIP + POSIX | ✅ | `rr_symlink_with_px` |
| 35 | zisofs `ZF` 圧縮エントリ (transparent decompression): `ZF` System Use entry (signature `pz`、log2 block size、非圧縮サイズ) + データ領域のポインタテーブル + 各ブロックの zlib ストリームを透過展開 | zisofs format 書面仕様 (`sources/zisofs_format.txt`、libisofs) + kernel `fs/isofs/rock.c`/`compress.c`、zisofs-tools `mkzftree` | ✅ | `zisofs_inflate` (block_shift 15-17 のみ受理、csize==0 は全ゼロブロック、ポインタ逆転/範囲外/truncate は reject)。`zisofs_roundtrip`, `zisofs_small_file`, `zisofs_rejects_bad_header`, `zisofs_rejects_bad_pointers`, `zisofs_rejects_bad_params` |

## Joliet 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 30 | SVD escape sequence `%/@` `%/C` `%/E` (UCS-2 level 1-3) で Joliet SVD を識別 | Joliet spec §"Escape Sequences" | ✅ | `test_iso9660_joliet_image` (`has_joliet`) |
| 31 | Joliet ツリーの file identifier は UCS-2BE、U+0000 で終端、`;version` 除去 | Joliet spec | ✅ | `test_iso9660_joliet_image` (lowercase 名) |
| 32 | Joliet ツリーは primary ツリーで Rock Ridge 名が得られなかった場合のみ使用 | 優先順位設計 | ✅ | RR fixture が RR 名で decode されることで確認 |
| 41 | UTF-16 surrogate ペア・Joliet level 3 超の UCS-2 拡張 | Joliet spec (UCS-2 規定 + 規格外入力の防御) | ✅ | `decode_ucs2` が `char::decode_utf16` で非 BMP を合成 (孤立 surrogate は `U+FFFD`)。`joliet_surrogate_pair_names` |
| 42 | Path Table の読み出し | ECMA-119 §8.4, §9.2 | ✅ | type-L path table を `PathTableEntry` として parse・`IsoImage.path_table` で公開 (欠落・範囲外は空で寛容、木走査が authoritative)。`path_table_matches_tree`, `path_table_absent_or_bad_extent_is_tolerated`, `test_iso9660_path_table` |
| 33 | multi-extent file (File Flags bit7: >4GiB 分割記録) | ECMA-119 §9.1.6 Table 10, §9.2 | ✅ | 同一 File Identifier の連続レコードをグループ化し extent を連結 (flags/unit/gap 不一致・未終端は reject)。`multi_extent_file`, `multi_extent_rejects_unterminated` |
| 34 | interleaved file (file unit size / interleave gap ≠ 0) | ECMA-119 §6.4.3, §9.1.7/8 | ✅ | unit ブロックを (unit+gap) 間隔で読み連結。`interleaved_file`, `interleave_gap_without_unit_rejected` |
| 39 | RRIP `PN`/`CL`/`RE` (PL は informational で読み飛ばし) | RRIP 1.12 §4.1.2, §4.1.5 | ✅ | `dev_t` を `IsoEntry` に公開、CL で relocated dir の実体 walk、RE 複製は列挙スキップ。`rr_pn_device`, `rr_cl_re_relocated_dir`, `rr_cl_rejects_bad_target` |

| 36 | El Torito boot record VD (type 0, sysid EL TORITO SPECIFICATION) + boot catalog 解釈: validation entry (key bytes/checksum/platform/id) + initial/section entries (indicator/media/segment/sectors/load LBA + image 抽出) を `IsoImage.el_torito` で公開 | El Torito 1.0 §2-2.5 (`sources/eltorito_spec_1.0.pdf`) | ✅ | `decodes_el_torito`, `el_torito_section_entries`, `rejects_bad_el_torito_validation`, `rejects_bad_el_torito_checksum`, `rejects_out_of_range_el_torito_catalog`, `skips_non_eltorito_boot_record`, `test_iso9660_eltorito_image` (bsdtar `-o boot=` 実 fixture `bsdtar-eltorito.iso` で payload 照合) |
## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|

| 37 | extended attribute record の内容解釈 | ❌ intentional scope | extent 開始ブロックへの加算のみ (読み飛ばし) |
| 38 | multi-session / UDF bridge / HFS ハイブリッドの別ツリー | ❌ intentional scope | primary + Joliet SVD のみ。UDF 実装時の一次仕様は OSTA UDF 2.60 / ECMA TR/112-2 (manifest `no_url_available` `osta-udf-260`) — ISO 9660 拡張ではなく別 FS 扱い |
| 39b | RRIP `PN`/`CL`/`RE`/`NM`/`PX`/`SL`/`TF`/`CE`/`SP`/`ST`/`ER` 以外の残エントリ (hardlink dev/inode、Apple `AA`/`BA` 等) | ❌ intentional scope | 読み飛ばし (decode に必須でない)。zisofs `ZF` は #35 で対応済み。Apple 拡張の資料は TN FL36 (`sources/apple_iso9660_fl36.html`) |
| 40 | ISO 9660 write | ❌ intentional scope | mkisofs/xorriso の領域 (write 実装時は producer oracle として利用可) |

## Fixture / interop

| fixture | 生成ツール | 内容 |
|---------|-----------|------|
| `tests/fixtures/iso9660/bsdtar-plain.iso` | bsdtar (libarchive ISO9660 writer) | plain ISO9660、大文字名 + `;1` |
| `tests/fixtures/iso9660/bsdtar-rockridge.iso` | bsdtar | SUSP 1.10 + RRIP 1.12、POSIX 名・mode・symlink |
| `tests/fixtures/iso9660/bsdtar-joliet.iso` | bsdtar | Joliet SVD、UCS-2BE 名 |
| `tests/fixtures/iso9660/bsdtar-eltorito.iso` | bsdtar -o boot= | El Torito boot record + catalog + boot.img payload |

`bsdtar -tf` / `bsdtar -tvf` による一覧・メタデータ照合済み (実ツール oracle)。
