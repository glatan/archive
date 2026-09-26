# rpm (RPM package)

| 項目 | 内容 |
|------|------|
| 基準仕様 | rpm.org Package Format documentation (`format_v6.html` / `format_header.html` / `format_lead.html`) + rpm `lib/cpio.c` (stripped payload 挙動) |
| 形式概要 | 96B Lead + Signature header + 8B パディング + Header + 圧縮 payload (cpio `newc` / stripped `07070X`) |
| 実装範囲 | **read のみ** (write / 署名検証は intentional scope 外) |

参照: <https://rpm-software-management.github.io/rpm/manual/format_v6.html> /
<https://rpm-software-management.github.io/rpm/manual/format_header.html> /
<https://rpm-software-management.github.io/rpm/manual/format_lead.html>

### Lead / ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | 96B Lead: magic `ED AB EE DB` + major/minor + type + archnum + name[66] + osnum + signature_type | format_lead.html | ✅ | `rejects_bad_lead_magic`, `RpmLead` |
| 2 | `type` は binary(0)/source(1) のみ受理 | format_lead.html | ✅ | `rejects_unknown_package_type` |
| 3 | Header structure: 8B magic `8E AD E8 01 00 00 00 00` + index count + data size | format_header.html | ✅ | `parse_header_section` |
| 4 | index entry = tag/type/offset/count (各 u32、offset は符号付き) | format_header.html | ✅ | `parse_header_section` |
| 5 | ヘッダ整数は big-endian | format_header.html | ✅ | `read_u32_be` 等 |
| 6 | データ型 CHAR/INT8/INT16/INT32/INT64/STRING/BIN/STRING_ARRAY/I18NSTRING (1-9) を認識。未知の型は reject | format_header.html | ✅ | `unknown tag type` |
| 7 | STRING 型は count=1 のみ受理 | format_header.html | ✅ | `STRING tag with count != 1` |
| 8 | Signature section 直後は 8B 境界までパディング | format_header.html ("8-byte aligned") | ✅ | `signature_end` 計算 |
| 9 | Signature の先頭 tag は `HEADERSIGNATURES`(62)、Header の先頭 tag は `HEADERIMMUTABLE`(63) の immutable region であること | format_header.html (header regions) | ✅ | `rejects_missing_region_tags` |
| 10 | 文字列 tag は NUL 終端、STRING_ARRAY は NUL 区切り列 | format_header.html | ✅ | `get_string`/`get_strings` |
| 11 | 整数型は要素サイズで整列 | format_header.html | ✅ | `entry_bytes` の offset 計算 |
| 12 | index/データ範囲の bounds 検査 (truncated → `UnexpectedEof`) | crate エラー規約 | ✅ | `rejects_*` 系 |

### payload

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | `RPMTAG_PAYLOADCOMPRESSOR` (tag 1125): gzip / bzip2 / lzma / xz / zstd / none を認識。tag 欠落時は gzip 既定 | format_v6.html + rpm 挙動 | ✅ | `payload_compressor` (bzip2/lzma 伸張経路は実装済み・個別テストなし) |
| 14 | 未認識 compressor 名 → `Unsupported` | 同上 | ⚠️ | `payload_compressor` の `Unsupported` 分岐実装済み (専用テストなし) |
| 15 | payload 伸張に output limit (bounded decode) を伝搬 | crate bounded-decode convention | ✅ | `bounded` ヘルパー |
| 16 | v4/newc payload は `cpio` decoder で entry を公開 (newcrc `070702` も受理し CRC 検証は cpio 側に委譲) | format_v6.html | ✅ | `decodes_uncompressed_newc_payload` |
| 17 | stripped payload: magic `07070X` + 8B hex file index、4B 整列、`fx == 0xffffffff` が trailer | rpm `lib/cpio.c` (rpm 独自形式、format_v6.html 参照) | ✅ | `parses_stripped_payload` |
| 18 | stripped payload の file size は payload に含まれず `RPMTAG_LONGFILESIZES` (5008) → `RPMTAG_FILESIZES` (1028) から取得。tag 不在は reject | rpm `lib/cpio.c` | ✅ | `rejects_stripped_payload_without_sizes` |
| 19 | stripped entry の名前は `BASENAMES`(1117) + `DIRNAMES`(1118) + `DIRINDEXES`(1116) で解決。不在時は hex index | rpm tag 定義 | ✅ | `resolve_stripped_name` |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 20 | system `cpio -o -H newc` + `gzip` で作った payload を decode | system interop | ✅ | `test_rpm_decode_system_compressed_payload` |
| 21 | crate で組み立てた `.rpm` を `bsdtar` (libarchive) が読み payload 内容を抽出 | system interop | ✅ | `test_rpm_crate_built_read_by_bsdtar` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 22 | Lead magic `ED AB EE DB` で `.rpm` を自動検出 | CLI detection | ✅ | `detect_rpm` |
| 23 | `archive extract` は payload entry を展開 | CLI semantics | ✅ | `extract.rs` の `Format::Rpm` アーム |
| 24 | fuzz algorithm `rpm` (self-regression 含む) | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 25 | `.rpm` の write (encoder) | — | ❌ | read-only scope (intentional) |
| 26 | OpenPGP 署名検証・payload/header digest 検証 | format_v6.html | ❌ | 暗号検証はコンテナレイヤの責務外 (intentional)。tag 値は API 経由で参照可能 |
| 27 | RPMTAG のパッケージ管理セマンティクス (依存関係・scriptlet・ファイル属性の install 意味) | rpm tags | ❌ | パッケージマネージャ層の責務 (intentional)。生 tag は `header.get_*` で取得可能 |
