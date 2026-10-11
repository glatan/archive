# arj (ARJ archive)

| 項目 | 内容 |
|------|------|
| 基準仕様 | ARJ technical note `TECHNOTE.DOC` (ARJ/UNARJ 配布物同梱、ARJ 2.x file format description)。所在: [Just Solve Wiki: ARJ](http://fileformats.archiveteam.org/wiki/ARJ) (安定した単一ファイル URL なし)。参照実装: UNARJ 2.41 (公式 decoder、制限付き freeware — ソースは ARJ archiver 以外の製品でのみ自由利用可。本 crate への取り込み不可、参照・oracle 用途のみ)、7-Zip `NArj`、newtua_dos (LGPL-3.0、XADMaster port、method 1-4) — manifest `no_url_available` の `unarj-source`/`newtua-dos` |
| 参照実装 | newtua_dos (LGPL-3.0-or-later、method4 の移植元・methods 1-3 の挙動参照)、XADMaster (garbled semantics の挙動参照)、UNARJ 2.41 (制限付き freeware、binary oracle のみ — ソース参照なし)、unar/7z (oracle)。詳細は基準仕様行および THIRD_PARTY_NOTICES arj 項・4a 節 |
| 形式概要 | `0x60 0xEA` + `u16le header size` の header ブロック列 (0 = end)。基本 header は 30B 固定 + NUL 終端 filename/comment + u32 header CRC + u16 ext size。main header の後に file header 列と data が続く |
| 実装範囲 | 展開 (read) は **method 0-4、no-data pseudo-method 8/9 (ARJ32)、file type 3 (directory) / 4 (label) / 5 (chapter label)、garbled (暗号化、パスワード必須)、および multi-volume (供給された parts の連結)** に対応する。作成 (write) は `ArjEncoder::with_method` による method 0-4 (圧縮効果が得られない場合は stored にフォールバック)、`with_password` による暗号化出力、および `finish_parts` による multi-volume 分割出力に対応する。`decode::volume_paths` (`std` feature) により、同一ディレクトリ内の sibling volume を自動探索できる。`decode_parts_with_password_bytes` で multi-volume + garbled の組み合わせにも対応する。出力上限を課す `decode_bounded` / `decode_bounded_with_password` も提供する。security envelope (flag 0x40) は `Error::Unsupported` で reject |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| method 0 (stored) | ARJ technical note | ✅ | ✅ | header/data CRC-32 検証 |
| file_type 3 (dir) / 4 (label) | ARJ technical note | ✅ | — | メタデータエントリ |
| method 1-3 (LZH st1 系) | TECHNOTE 概略 + newtua_dos/UNARJ de facto 参照 | ✅ | ✅ | 15-bit window の静的 Huffman (LHA st1 共有実装)。encode は `with_method(1-3)` → `compress::lzh::st1_enc` |
| method 4 (fastest LZSS) | TECHNOTE 概略 + newtua_dos de facto 参照 | ✅ | ✅ | 0x8000B window LZSS。encode は `with_method(4)` → `method4::encode` |
| garbled (password) | ARJ technical note | ✅ | ✅ | `decode_with_password{,_bytes}` / `ArjEncoder::with_password` (#20) |
| multi-volume | ARJ technical note | ✅ | ✅ | `decode_parts` で parts 供給、encode は `finish_parts` で分割 emit (自己 roundtrip 検証のみ。外部ツールによる multi-volume interop は未検証) |

### ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | signature `0x60 0xEA` + `u16le hsize`、hsize=0 で終端 | ARJ tech note §header | ✅ | `roundtrip` |
| 2 | 基本 header 30B: first_hdr_size(1) / version(1) / min_ver(1) / host_os(1) / arj_flags(1) / method(1) / file_type(1) / reserved=garble_modifier(1) / dos_time u32 / packed u32 / orig u32 / crc32 u32 / filespec_pos u16 / access_mode u16 / host_data u16 | ARJ tech note | ✅ | `roundtrip` (decode.rs のフィールド順コメントに準拠)。旧 ARJ writer の 28B 基本 header (`first_hdr_size` ≥ 28) も受理 |
| 3 | filename + comment は NUL 終端文字列 (first_hdr_size の後) | ARJ tech note | ✅ | `read_cstr` |
| 4 | header CRC-32 は hsize バイト本体に対して、header 直後に u32le 格納、不一致は reject | ARJ tech note | ✅ | `rejects_bad_header_crc` |
| 5 | extended header: CRC 直後の u16 size (0 = なし) + data + u32 CRC を skip | ARJ tech note | ✅ | ext サイズ処理 (skip 経路実装済み。現行 fixture は全て ext size 0 で、ext>0 を feed する専用テストは未整備) |
| 6 | 先頭 header は main header として読み、entry として返さない | ARJ tech note | ✅ | `roundtrip` |

### メソッド / データ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | method 0 (stored): data は生バイト列、packed == orig 必須 | ARJ tech note | ✅ | `roundtrip` |
| 8 | file_type 3 (directory) / 4 (volume label) は payload なし | ARJ tech note | ✅ | `dir_entry` (type 3)。type 4/5 の専用テストは `test_arj_chapter_label` (type 5) のみ — 処理は `matches!(3..=5)` の共有パス。file_type 1 (text) は binary と同じく file として decode |
| 9 | method 1-3 (LZH st1、15-bit window) decode、method >=5 は `Error::Unsupported` | ARJ tech note 概略 + newtua_dos | ✅ | `test_arj_compressed_methods`, `test_arj_rejects_compressed_method` (method 5/6/7/10/255) |
| 10 | method 4 (fastest LZSS、0x8000B window) decode | ARJ tech note 概略 + newtua_dos | ✅ | `test_arj_compressed_methods`, `arj::method4` 単体 |
| 10a | arj_flags bit0 (garbled/password): password API で XOR 解除、未供給/誤 password は reject | ARJ tech note | ✅ | `test_arj_garbled` |
| 10b | arj_flags bit2 (multi-volume): `decode_parts` で供給 parts を filename で連結 | ARJ tech note | ✅ | `test_arj_multi_volume`, `test_arj_multi_volume_three_way` |
| 21 | multi-volume の自動ファイル探索 | crate extension | ✅ | `decode::volume_paths` (`std` feature) で `.arj` / `.aNN` の sibling ファイルを順序付きで列挙する。`volume_paths_discovers_siblings`, `test_arj_volume_paths_discovery_roundtrip` |
| 11 | entry data CRC-32 を検証、不一致は reject | ARJ tech note | ✅ | decode 内検証 |
| 12 | bounds 検査 (truncated signature/header/data、st1 block count=0 → エラー) | crate エラー規約 | ✅ | `test_arj_rejects_truncated`, `test_st1_zero_block_count_rejected` (共有 `compress::lzh::st1`), `test_fuzz_regression_arj_1_corrupt` |
| 12a | `decode_bounded` / `decode_bounded_with_password`: member 宣言 `orig` の累計が `max_output` を超えた時点で `Error::OutputLimitExceeded` | crate エラー規約 | ✅ | `decode_bounded_enforces_declared_orig`。fuzz harness の `Arj*`/`ArjGarbled` は bounded 経路を使用 |
| 13 | filename は UTF-8 必須 | crate エラー規約 | ✅ | `read_cstr` |
| 19a | method 8/9 (ARJ32 no-data pseudo-method) decode と file_type 5 chapter label の受理。method 8 は CRC 非検証、method 9 は空 payload の CRC 検証を行う差異あり | ARJ32 系 de facto | ✅ | `test_arj_method8_9_no_data`, `test_arj_chapter_label` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 14 | `ArjEncoder`: main header (host_os=unix) を先頭に出力し、file header + data、dir は file_type 3。`with_method` で method 0-4 を選択 (1-3 は st1 共有エンコーダ、4 は `method4::encode`、圧縮不利時は method 0 fallback)、`finish_parts` で multi-volume 分割 | ARJ tech note | ✅ | `roundtrip`, `dir_entry`, `st1_methods_roundtrip`, `test_arj_method4_encode_roundtrip`, `test_arj_finish_parts_roundtrip` |
| 15 | 終端 `0x60 0xEA` + `u16` 0 を付与、各 header に ext size 0 を付与 | ARJ tech note | ✅ | 往復テスト |
| 20a | 暗号化 (garbled) の write | ARJ tech note | ✅ | `ArjEncoder::with_password` で対応 (`ungarble` は対称変換のため encode/decode で共用)。`garbled_roundtrip`, `garbled_write_requires_password_decode`, `test_arj_garbled_write_roundtrip` |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 16 | crate 生成 method-0 `.arj` を `7z` が list/extract | system interop | ✅ | `test_arj_7z_list_interop` |
| 16a | mirror encoder 生成の `.arj` を `unar`/`7z` が byte-for-byte extract (テストの member は method 0/1/4、wire 同一の 2/3 は間接カバー) | system interop | ✅ | `test_arj_oracle_extract` (oracle 非存在時 skip) |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | `0x60 0xEA` signature で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_arj` (同上: spawn 統合テスト基盤は未整備)。既知制約: CLI の `--password` は arj に配線されておらず、garbled arj は CLI では展開不可 (ライブラリ API `decode_with_password*` のみ) |
| 18 | fuzz harness `arj` で encode→decode 往復。`arj-1`〜`arj-4` が compression method 別、`arj-garbled` が garbled (password) エントリをカバー | fuzz 規約 | ✅ | `Algorithm::Arj` 他 |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 19 | method 5-7 / security envelope は非対応 | ❌ intentional scope | method 5-7 は歴史的に未定義のまま `Error::Unsupported`。security envelope (arj_flags 0x40) は公開アルゴリズム記述がないため `parse_volume` で `Error::Unsupported` reject (`rejects_security_envelope`)。method 8/9 と chapter label の対応は #19a。decode 参照実装は manifest `no_url_available` (`newtua-dos` が安全側、`unarj-source` は制限付き freeware のため参照のみ)。oracle は `unar`/`7z` (Debian `arj` は non-free) |
| 20 | パスワードなし garbled decode | ❌ intentional scope | 暗号化の性質上不可能。garbled write の対応は #20a |
| 22 | method 5+ の write は非対応 | ❌ | `with_method` は 0-4 のみ受理 (method 5+ は `InvalidData`)。method 8/9 は no-data pseudo-method のため write の対象外。圧縮不利時は method 0 fallback |

### 実装メモ

- `first_hdr_size` が基本ヘッダ (30B) を超える場合、超過分は拡張ヘッダとして読み飛ばす (内容は解釈しない)。
- ファイルコメントのクレームテストは行っていない (ヘッダ直後の NUL 区切り文字列として受理のみ)。
- method 1-3 は LHA lh4/lh5 と同系の静的 Huffman LZ (15-bit window、position テーブル 5-bit count) を `compress::lzh::st1` / `st1_enc` 共有実装で decode/encode (wire 形式は method 間で同一、method byte は effort level のタグ)。method 4 は ARJ 独自の fastest LZSS (`arj::method4`)。
- garbled は「password 各バイト + modifier」の巡回 XOR で packed data を解除してから decode。password 未供給で garbled に遭遇した場合は `Error::Unsupported`、解除後のデータ CRC 不一致は `Error::InvalidData`。
- multi-volume は flag bit2 (continued) の member を同一 filename の後続 header で接続する。継続 member の packed size は当該 volume 内の断片サイズを指す。
- arj_flags の残 bit: 0x08 (extended file-start-position) は `first_hdr_size` が基本 header を超える場合の超過分 skip で暗黙受理 (内容は解釈しない)。0x10 (path separator translated) は encoder が `FLAGS_BASE=0x10` として全 member に設定。
- main header (file_type=2) はその method byte に security format version を格納する (encoder は 2 を emit)。main header は entry として返さない。
