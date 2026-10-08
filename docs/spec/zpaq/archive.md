# ZPAQ — archive format (zpaq206 §8-§10) + crate-local 契約

対象: `src/archive/zpaq/` (decode.rs, encode.rs, jidac.rs, mod.rs)

基本方針: **decoder は upstream parity で lax、encoder は strict**。§7 は「decompresser は compliant でないデータを受理してよい」「compressor は適合データを出力する責任がある」と定めるため、decode 側で追加検査しない項目は各備考欄に "lax" と明記する。

## §8 streaming archive

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 33 | named segment で file を構成、空 filename は直前 file の continuation (comment は破棄)。先頭 segment の空 filename は continuation でなく無名 file | §8 | ✅ | `test_decode_merges_continuation_segment` (comment 破棄を含む), `test_decode_leading_empty_filename_is_standalone`, `test_decode_bounded_merges_continuation_segment`, `test_decode_journal_versions_merges_continuation_segment`。`ZpaqEncoder::add_entry` は空 filename を emit 可能で、decode は §8 continuation 規則で受理 |
| 34 | streaming archive 内の全 segment comment は `jDC\x01` で終わらない | §8 | ✅ | `test_rejects_comment_ending_jdc_marker` (encode で reject)。decode は upstream 同様 lax |
| 35 | streaming / journaling の混在は適合外 | §8 | ✅ | `jidac_rejects_non_journal_stream`。混在検出: `decode.rs` (journal 中の非 journal segment) と `jidac.rs` (journal 中の streaming block / 非 journal 入力) で reject |
| 36 | 1 transaction につちょうど 1 segment | §8 | ✅ | `emit_block`/`ZpaqJournalEncoder`/`encode_jidac` は 1 block = 1 segment で emit。decode は upstream 同様 lax |
| 37 | comment = `"size jDC\x01"` (size = block payload の byte 数 ≤ 4294967295、pad なし) | §8 | ✅ | `parse_comment` (手書き digit parse) が `jDC\x01` 終端を検査し size を block payload 長と照合。`emit_block`/`JidacAppender` が `"N jDC\x01"` emit |

## §8 journaling archive (JIDAC)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 38 | filename = `jDC` + date(14) + type(c/d/h/i) + num(10) (28 chars)、昇順・num ≥ 1・date は現在時刻より過去 | §8 | ✅ | `parse_filename` + `jidac_rejects_bad_name_and_date` / `jidac_rejects_zero_num` (num=0 reject)。昇順・date 過去の検査は upstream 同様 lax (encoder は UTC now・連番で emit) |
| 39 | c block: `csize[8]` = 当該 transaction の後続 d block 列の総圧縮サイズ、`2^63..` は archive 終端マーカー (後続全 block を ignore) | §8 | ✅ | `jmp<0` で archive 終端、`decode`/`encode_jidac` 往復 |
| 40 | d block: fragment ID は連番 (n..n+f-1)・一意・ID 0 不可・先行 c block の n 未満不可 | §8 | ✅ | `jidac_rejects_zero_num` (num=0 reject)。lax: ID を飛ぶ num は upstream 同様 empty fragment padding で受理、h record の重複 ID は上書き、c の n 未満 ID は未検査 |
| 41 | h block: d block と対、bsize (d の圧縮後サイズ)、sha1+fsize 一覧、fsize 合計 = fragment サイズ | §8 | ✅ | fsize を実 fragment 長と照合 (sha1 は記録のみ、upstream parity)。lax: bsize と d block 実サイズの照合は upstream 同様未検査 |
| 42 | i block: update (date>0) / delete (date=0)、name は UTF-8・`/` 区切り・≤65535 bytes、na attr 長 ≤65535 (`w`/`u` prefix 解析)、ni ptr は同一 transaction より前の fragment を必ず指す | §8 | ✅ | `decode_jidac` の ptr 解決・delete・`w`/`u` attr pack/unpack (`u x.y`/`w sec.usec` のテキスト表現は upstream de facto)、`jidac_rejects_oversized_filename` (name ≤65535)、decode で `na > 65535` を reject、`jidac_append_roundtrip_and_delete` / `test_zpaq_journal_delete_visibility`。ptr の「先行 fragment」条件は decode 時の fragment data 解決で実質保証 |
| 43 | index archive (d block なし、c block の csize=0) の decode: fragment 位置未知でも file 名/date/attr/fragment table を読み取る | §8 | ✅ | `decode_jidac_index` → `JidacIndex` (versions/files/fragments/committed_len)。`decode_jidac` は fragment data 解決を要し `Error::InvalidData("zpaq jidac: missing fragment")` |

## crate-local 契約 (wire レベルは §8 準拠、層の意味論は crate 独自)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 44 | journaling transaction: reserved prefix + commit marker 対、committed latest view / version history / uncommitted tail ignore | — | ✅ | `ZpaqJournalEncoder`, `decode_journal_versions`, `test_decode_journal_versions_ignores_uncommitted_tail`, `test_journal_encoder_appends_committed_transaction`, `test_journal_encoder_rejects_reserved_filename_prefix` |
| 45 | transaction commit は journal entry 全体 (全 byte・全 block) を対象とし、通常の `decode` で全 byte が見える | — | ✅ | crate-local journal は filename `@zpaqj1:` prefix + comment `@zpaqj1-op:` marker を持つ通常の streaming segment 列なので、upstream `zpaq l` でも独立 file として enumerate される (`jDC\x01` は upstream JIDAC の marker であり、crate-local journal とは別物 — streaming encoder はそれを reject、#34)。`decode_journal_*` は全 segment を parse するため 2+ block 横断も正確 |
| 46 | plain archive (plain/journal marker なし) を committed put として受理 | — | ✅ | `test_decode_journal_latest_treats_plain_archive_as_committed_puts` |
| 47 | `ZpaqArchiveEditor`: plain archive / committed latest view の import → push/put/delete → 1 archive への materialize | — | ✅ | `test_archive_editor_from_archive_put_and_delete`, `test_archive_editor_from_journal_latest_materializes_plain_archive`, `test_zpaq_archive_editor_rewrites_imported_archive`, `test_zpaq_archive_editor_materializes_journal_latest_view` |
| 48 | `decode_bounded` / `OutputLimitExceeded` による出力上限 | — | ✅ | `decode_bounded_enforces_limit` (codec), `test_decode_bounded_limits_total_output`, `test_decode_bounded_merges_continuation_segment` (archive) |
| 49 | append-as-new-block: 既存 header を parse して再利用、model state なし追記 | — | ✅ | `test_zpaq_archive_append_to_existing_roundtrip`, `test_append_to_archive_preserves_existing_entries_and_header`, `test_append_to_archive_rejects_trailing_bytes` |
| 50 | upstream wire interop (level 1-3・stored・PCOMP・SHA-1・JIDAC emit/append) | — | ✅ | `decode_upstream_fixtures`, `decode_jidac_appended_mixed` (upstream `zpaq a` fixture)、dev-only env-gated helper `dump_jidac_fixture` / `decode_upstream_jidac_oracle` / `decode_upstream_jidac_heavy_pcomp`、fuzz oracle `ArchiveSpec::Zpaq` |
| 51 | `.cfg` config 言語コンパイラ (`compile_config`) → `CustomModel` 橋渡し | upstream de facto | ✅ | `compiles_builtin_models_byte_exact`, `mid_cfg_args_shift_table_sizes`, `structured_control_flow`, `do_while_lowers_to_backward_jt`, `compiled_model_encodes_identically_to_builtin`, `compile_config_with_args` |
| 52 | `CustomModel` authoring + `encode_with_model`、`CustomModel::with_pcomp` で PROG emit | upstream de facto | ✅ | `custom_model_cm_avg_roundtrip`, `custom_model_pcomp_roundtrip`, `custom_model_pcomp_validation` |
| 53 | `ZpaqCodec` trait surface (Codec impl) | — | ✅ | `archive/zpaq/mod.rs` `ZpaqCodec` + `test_archive_codec_decode_roundtrip`、`compress/zpaq/mod.rs` にも同名 `ZpaqCodec` (raw stream 用) + `zpaq_codec_roundtrip` |

## §9 encrypted format

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 54 | encrypted format (AES-256 CTR + salt 32B + Scrypt N=16384,r=8,p=1) | §9 | ❌ | intentional scope (この crate は暗号層を対象外) |

## §10 implementation notes / multi-part archive

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 55 | fragment 境界の推奨定義 (byte 絶対値の rolling hash、サイズ 4096..520192 除去後、平均 ≈2^16・最大 65535) | §10 | ✅ | `split_fragments` は upstream `zpaq.cpp` 移植 (seed/rate/edge formula 一致)、`jidac_append_dedup_reuses_fragments` / `decode_jidac_appended_mixed` で upstream 生成 fragment 列と整合 |
| 56 | multi-part archive (part00 index + partNN) の emit | §10 | ❌ | intentional scope。part00 index archive は `decode_jidac_index` で読み取り可、part 連結は caller が concat すれば decode 可 |
| 59 | encoder は modeled ecd 内で 0 byte が 3 連続を超えない出力を保証し、EOS 後に end-of-segment marker `(0 0 0 0)` を書く (decoder の高速 scan 前提) | §2, §10 | ✅ | `arithmetic.rs` の encoder normalization が 4 連続ゼロを emit しない invariant を維持、`encode.rs` が EOS 後に 4 ゼロ byte を出力 |

## 未実装事項 (仕様外・upstream 機能)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 57 | ZPAQL JIT 実行経路 (upstream `libzpaq.cpp` の x86-64 codegen) | upstream `libzpaq.cpp` | ❌ | intentional scope。意味論は interpreter と等価 (interop fixture 検証) のため wire 表現は完全 |
| 58 | upstream compact method string パース (`-m x6ci1` 系) | upstream CLI | ❌ | intentional scope (`.cfg` config 言語は対象。method string は `compress/zpaq` 単位選択で代替) |

## 既知の差分・注意点

- 上表で "lax" と明記した decode 側の受理は全て §7 の「decompresser は compliant でないデータを受理してよい」の範囲であり、upstream `zpaq`/`libzpaq` も同様に未強制 (filename/comment 上限、jDC 昇順・date 過去、d-block ID skip/c 未満、h-block bsize 照合等)
- `decode` は data order で emit するため in-archive ソートは「現在の jDC 対応の補助機能」であり正式 spec ではない
- 現行 crate の decode は遅延 flush 方式: transaction 単位の「真に uncommitted な末尾」を commit marker まで遡って除外する設計で、upstream journal の単純 prefix-slurp とは意味論が異なる (uncommitted 末尾切り捨てで有効 journal 内容を失わないことを `test_decode_journal_*` 系で担保)
