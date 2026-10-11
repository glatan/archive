# LZW (Unix compress `.Z` フォーマット)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [`ncompress`](https://github.com/vapier/ncompress) ([`compress42.c` @ ncompress-4.2.4](https://github.com/vapier/ncompress/blob/ncompress-4.2.4/compress42.c)、Unlicense、ローカルスナップショット: `docs/spec/sources/ncompress_4.2.4_compress42.c`) のデファクト標準に準拠 |
| 参照実装 | ncompress `compress42.c` (public domain、de facto 標準。encoder の block-mode adaptive reset は `cl_block()` の設計を動作参照として踏襲)。system `compress`/`uncompress`/`gzip` は統合テストの oracle、`tests/fixtures/lzw/hello.Z` は system `compress` 生成 fixture。詳細: THIRD_PARTY_NOTICES LZW 項 |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー `0x1F 0x9D` 検証 | ncompress `compress42.c`: file header | ✅ | `test_invalid_magic` |
| 2 | ヘッダー長チェック (3バイト未満) | ncompress `compress42.c`: file header | ✅ | `test_input_too_short` |
| 3 | max_bits 範囲チェック (9-16) | ncompress `compress42.c`: file header | ✅ | `test_max_bits_out_of_range` |
| 4 | ブロックモード (クリアコード 256) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_large` (辞書フル→クリア) |
| 5 | 可変幅コード 9-16ビット | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_max_bits_range`, `test_roundtrip_large` |
| 6 | コード幅遷移タイミング (ncompress互換) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_large` (max_bits=10, 512バイト) |
| 7 | LSB-first ビットパッキング | ncompress `compress42.c`: bit packing | ✅ | `test_read_code_lsb_first` |
| 8 | KwKwK 特殊ケース (code == next_code) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_kwkwk` |
| 9 | 空データの圧縮/伸張 | ncompress `compress42.c` | ✅ | `test_roundtrip_empty`, `test_empty_compressed_data` |
| 10 | 単一バイトの圧縮/伸張 | ncompress `compress42.c` | ✅ | `test_roundtrip_single_byte` |
| 11 | 全バイト値 (0-255) のラウンドトリップ | ncompress `compress42.c` | ✅ | `test_roundtrip_all_bytes` |
| 12 | 不正コード検出 (code > next_code) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_code_out_of_range` |
| 13 | system compress 互換性 | ncompress `compress42.c` compatibility | ✅ | `test_lzw_decode_system_compress_fixture` (統合テスト) |
| 14 | `encode_writer` / `decode_reader` (std::io) | ncompress `compress42.c` | ✅ | doctest |
| 15 | Header byte 2: max_bits (bits 0-4) + block_mode flag (bit 7) | ncompress header layout | ✅ | デコーダーで parse |
| 16 | Dictionary 初期化: codes 0-255 = single byte, code 256 = clear code (block mode) | ncompress dictionary | ✅ | 実装済み |
| 17 | First emitted code は raw byte (0-255) | ncompress code stream | ✅ | 実装済み |
| 18 | Non-block-mode: dictionary が full になっても reset しない | ncompress block_mode=false | ✅ | `test_roundtrip_non_block_mode`, `test_non_block_mode_header_flag`, `test_non_block_mode_decode`, `encode_with_full_options()`。non-block 時の辞書初期コードは本実装では encode/decode 両側 256 に統一 (compress42.c は encoder L1374 が無条件に `free_ent = FIRST (257)`、decoder L1659 が 256 の非対称を持つため decoder 規約に合わせた) |
| 19 | Max dictionary size: 2^max_bits entries | ncompress dictionary growth | ✅ | `test_fuzz_regression_dict_full_wraparound` (辞書フル境界: next_code=65536), `test_roundtrip_dict_full_boundary_all_max_bits`, `test_roundtrip_non_block_dict_full`, `test_decode_chain_code_65535`, `test_decode_chain_prefix_65535` |
| 20 | Code width increase タイミング: ncompress 互換 (early change) | ncompress code stream | ✅ | item 6 で部分記載 |
| 21 | EOF trailing partial code group: 不完全な最終 code group は無視 | ncompress EOF handling | ✅ | デコーダーで暗黙的に処理 |
| 22 | ヘッダ byte2 の予約ビット 0x20/0x40 | compress42.c:234-237 ("Masks 0x20 and 0x40 are free") | ✅ | ncompress は無視するが本実装は `RESERVED_FLAGS = 0x60` で拒否 (参照実装より厳格)。`test_lzw_decode_rejects_reserved_header_flags` |
| 23 | エンコーダの ratio ベース CLEAR (CHECK_GAP=10000 毎に圧縮率低下で CLEAR 出力) | compress42.c:1418-1446 | ✅ | block_mode で CHECK_GAP=10000 バイトごとに `ratio = (bytes_in << 8) / bytes_out` を評価し、非改善 (`ratio <= old_ratio`) で CLEAR emit。compress42.c との差異: ① `!stcode` ゲート (辞書満杯後のみ評価、compress42.c:1418) を持たず常時評価する、② 等値 ratio でも CLEAR を出す (compress42 は `rat >= ratio` で keep)。いずれも emit タイミングのみの差で、生成ストリームは常に valid。`test_ratio_clear_on_worsening_input` `test_no_ratio_clear_when_ratio_improves` |
| 24 | group-of-8 resync はブロックラン起点 (`boff`) 相対 | compress42.c:1381, 1404-1405, 1441-1443 (encoder `boff`), 1700-1710, 1730-1731 + `resetbuf` (decoder) | ✅ | CLEAR/width-bump 後の pad/resync は body 先頭ではなく直前の resync 到達位置から測る。到達位置が新たなブロックラン起点になる (width bump も起点を更新)。non-block mode では bump が mid-group に位置し得るため encoder は bump 時にもゼロ pad を emit する。`test_clear_pad_originates_at_block_run_start`, `test_clear_pad_run_relative_multiple_runs`, `test_fuzz_regression_clear_pad_run_start`, `test_clear_resync_originates_at_bump_landing`, `test_clear_body_relative_pad_is_corrupt` |
| 25 | dict 満杯時 CLEAR の emit 位置と decoder の phantom bump との整合 | compress42.c:1698-1710 (decoder `free_ent > maxcode` 無条件拡幅), 1402 (encoder `n_bits < maxbits` ガード) | ✅ | compress42.c 系 decoder (gzip unlzw, ncompress -d) は `free_ent > maxcode` で `n_bits < maxbits` ガードなしに拡幅する (phantom bump) ため、max_bits=9 のストリームでも run の 257 番目の code から 10bit で読む。encoder は dict 満杯時 CLEAR を emit #256 (辞書が丁度満杯になった時点で即 emit) に配置し run を 256 codes 以内に抑え、gzip/ncompress 双方で復号可能にする。一方 decoder は phantom bump を意図的に再現しない (`code_bits < max_bits` cap 維持): 実在する -b9 ストリームの生成元は ncompress のみであり、同ツールは phantom bump のないストリームを出力するため、phantom bump を再現するとかえって正常に復号できなくなる。`test_dict_full_clear_is_emit_256_max_bits_9`, `test_fuzz_regression_bits9_phantom_bump_artifacts`, `test_phantom_bump_compat_all_max_bits`, `test_lzw_encode_bits9_decoded_by_system_uncompress` (統合テスト) |
| 26 | デコーダの厳格化: 先頭コードおよび CLEAR 直後のコードは literal (<256) 必須 | compress42.c:1715-1720 (先頭 `code >= 256` で abort), 1726-1734 (CLEAR 後 `free_ent = FIRST - 1` で code > 256 を corrupt 扱い) | ✅ | compress42 は CLEAR 直後の連続 CLEAR (code=256) を受理するが本実装は literal のみ受理 ("first code after clear must be a literal") — 参照実装より厳格。`test_literal_after_clear_required` |

---

## 外部ツール非互換 (intentional scope)

以下は `ncompress` (system `compress`/`uncompress`) 固有の動作であり、本ライブラリの欠陥ではない。
fuzz の `original-compress` / `original-decompress` パターンにおける誤検知を防ぐため、`fuzz/src/known_issues.rs` で除外対象としている。

| # | 項目 | 対象 variant | 理由 |
|---|------|------------|------|
| A | `ncompress` による空入力の拒否 | `lzw`, `lzw-bits9` | `compress`/`uncompress` は空入力に対して exit status 2 で終了する。ライブラリは空データを正常処理する (`test_roundtrip_empty`, `test_empty_compressed_data`) |
| B | `compress -b 9` の非可逆 roundtrip | `lzw-bits9` | `ncompress -b 9` は一部の入力に対してロッシーな roundtrip を起こす外部ツール自身のバグ。system `uncompress` でも元データを復元できない場合がある。不整合の原因: ncompress の encoder は `n_bits < maxbits` ガード (compress42.c:1402) で拡幅を止めるが、decoder は `free_ent > maxcode` で無条件に拡幅 (phantom bump, compress42.c:1698) するため、辞書満杯後の code 幅が encoder/decoder 間で不整合となる (要件 #25 参照) |

---

## 特許ステータス (Patent Status)

LZW の Unisys 特許 (US 4,558,302、Welch) は米国で 2003-06-20 に失効し、欧州各国・カナダ・日本の対応特許も 2004 年中に全て失効済み (THIRD_PARTY_NOTICES LZW 項参照)。本モジュールの実装・配布に特許上の障害はない。これは透明性のための記録であり、法的助言ではない。網羅的な特許調査 (freedom-to-operate opinion) は実施していない。

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 26 |
| ❌ 未実装  | 0 |
| **合計** | **26** |


---
