# ZX0 (v2)

| 項目 | 内容 |
|------|------|
| 形式概要 | Einar Saukas の ZX0 v2 が使用する raw LZ77 ストリーム。制御ビット列とデータバイトがインターリーブする形式で、8bit CPU での高速伸張に最適化されている。magic・コンテナヘッダ・チェックサムは持たない |
| 基準仕様 | [ZX0 README](https://github.com/einar-saukas/ZX0) "File Format" (ローカルスナップショット: `docs/spec/sources/zx0_README_v2.2.md`) + 参照実装 `dzx0.c` / `compress.c` (Einar Saukas, BSD 3-Clause) |
| 実装 | `archive::compress::zx0` (decode / decode_bounded / encode)。pure-Rust 実装 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| v2 forward / non-inverted | [ZX0 README](https://github.com/einar-saukas/ZX0) + `dzx0.c` (BSD-3) | ✅ | ✅ | |
| v1 (`-c` classic) | [ZX0 README](https://github.com/einar-saukas/ZX0) | ✅ | ❌ | `decode_classic` / `decode_classic_with_prefix` (offset-MSB Elias 非反転のみ差分) |
| backward (`-b`) / inverted (`-i`) | [ZX0 README](https://github.com/einar-saukas/ZX0) | ❌ | ❌ | intentional scope |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 制御ビットは MSB-first。制御バイトとデータバイトは消費順にインターリーブされる | dzx0.c `read_bit`/`read_byte` | ✅ | `zx0_reference_vector_text` (統合) |
| 2 | インターリーブ Elias gamma: `value=1`、continuation bit 0 のあいだ `value = value*2 + databit`、1 で終端 | README / dzx0.c `read_interlaced_elias_gamma` | ✅ | `decode_minimal_literal` + 参照ベクタ全般 |
| 3 | 先頭ブロックは常に literal で indicator bit を持たない | README | ✅ | `zx0_reference_vector_*` (統合) |
| 4 | literal ブロック: `elias(len)` + len バイト (v2 literal エリアスのデータビットは非反転) | README / compress.c | ✅ | `zx0_reference_vector_text` (統合) |
| 5 | literal 後の bit: 0 = copy-from-last-offset、1 = new-offset | dzx0.c state machine | ✅ | `zx0_reference_vector_rep_offset` (統合) |
| 6 | copy-from-last-offset: `elias(len)` で前回 offset を再利用 | README | ✅ | `zx0_reference_vector_rep_offset` (統合) |
| 7 | new-offset: `elias((off-1)/128 + 1)`、データビットは v2 で反転。256 は EOF マーカ | README / compress.c `invert_mode` | ✅ | `zx0_reference_vector_*` (統合) |
| 8 | offset LSB は専用 1 バイト `((127 - (off-1)%128) << 1)`。decode: `off = msb*128 - (byte>>1)` (参照エンコーダの最大は 32640。デコーダは出力済み範囲の検証のみで 32640 上限の明示検査は行わない) | compress.c / dzx0.c | ✅ | `zx0_reference_vector_*` (統合) |
| 9 | LSB バイトの bit0 は直後の `elias(len-1)` の先頭ビットとして消費される (backtrack) | dzx0.c `backtrack` | ✅ | `zx0_reference_vector_*` (統合) |
| 10 | match 長は `elias + 1` (最小 2 バイト) | compress.c `length-1` | ✅ | `zx0_reference_vector_rep_offset` (統合) |
| 11 | ストリーム末尾は new-offset indicator + elias(256)。EOF 時点で入力を消費しきること (余剰バイトはエラー) | dzx0.c EOF 検証 | ✅ | `zx0_rejects_malformed` (統合) |
| 12 | 初期 last_offset = 1 | zx0.h `INITIAL_OFFSET` | ✅ | `zx0_reference_vector_rep_offset` (統合) |
| 13 | 空入力は空出力に対応 (フォーマット上は空出力を表現不可; crate 内部規約として受理) | crate contract | ✅ | `empty_input` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 14 | 切り詰め制御ビット / リテラル / LSB バイトの拒否 | dzx0.c truncated input | ✅ | `rejects_truncated`、`zx0_rejects_malformed` (統合) |
| 15 | match offset が出力済みバイト数を超過する場合は拒否 | dzx0.c `write_bytes` 検証 | ✅ | `rejects_bad_offset` |
| 16 | EOF 後の余剰バイトの拒否 | dzx0.c `input too long` | ✅ | `zx0_rejects_malformed` (統合) |
| 17 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 18 | decode→encode→decode ラウンドトリップ (テキスト / 反復 / バイナリ) | README | ✅ | `roundtrip_various`、`zx0_roundtrips` (統合) |
| 19 | エンコーダは greedy 単一候補マッチ探索。参照実装の optimal parsing とは出力が異なる (仕様上正当) | 実装選択 | ✅ | roundtrip で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 20 | CLI `--format zx0` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 ZX0 v2.2 (Einar Saukas) は BSD 3-Clause。本実装は README のフォーマット記述と `dzx0.c` の動作解析から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `ZX0_*` は参照 C コンプレッサ (ZX0 v2.2) をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証): literal+match 混在、rep-offset、長マッチ連鎖を含む。
- backwards モード (`-b`、後方読み)、inverted モード (`-i`) は intentional scope 外。classic v1 (`-c`、offset-MSB Elias 非反転) と prefix decode (`decode_with_prefix`/`decode_classic_with_prefix`) は対応済み。
- ZX0 は ZX Spectrum 等のレトロプラットフォーム向けに設計された codec で、同一フォーマットの decompressor が Z80/6502/68k/x86 等多数のアセンブリ実装を持つ。
- 実装メモ: Elias gamma 値には `1 << 20` の安全性ガードを設けている (無制限増大する malformed 入力の DoS 防止。フォーマット定義ではなく実装追加の制限)。
