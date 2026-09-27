# ZX2

| 項目 | 内容 |
|------|------|
| 形式概要 | Einar Saukas の ZX2 が使用する raw LZ77 ストリーム。ZX1 の minimalist 版で、new-offset フィールドが 1 バイト固定 (最大 offset 255)。制御ビット列とデータバイトがインターリーブする。magic・コンテナヘッダ・チェックサムは持たない |
| 基準仕様 | [ZX2 README](https://github.com/einar-saukas/ZX2) "File Format" (ローカルスナップショット: `docs/spec/sources/zx2_README_v1.1.md`) + 参照実装 `dzx2.c` / `compress.c` (Einar Saukas, BSD 3-Clause) |
| 実装 | `archive::compress::zx2` (decode / decode_bounded / encode)。pure-Rust 実装 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| forward / デフォルト (initial offset=1, len=elias+1) | [ZX2 README](https://github.com/einar-saukas/ZX2) + `dzx2.c` (BSD-3) | ✅ | ✅ | |
| backwards (`-b`) | [ZX2 README](https://github.com/einar-saukas/ZX2) | ❌ | ❌ | intentional scope |
| ignore default offset (`-z`) | [ZX2 README](https://github.com/einar-saukas/ZX2) | ❌ | ❌ | intentional scope (初期 last_offset=0) |
| skip length increment (`-x`) | [ZX2 README](https://github.com/einar-saukas/ZX2) | ❌ | ❌ | intentional scope (min_length=1 で長をデクリメントせず格納) |
| limit block length (`-y`) | [ZX2 README](https://github.com/einar-saukas/ZX2) | ❌ | ❌ | intentional scope (elias 値 <=255 の制約。デコーダメモリ削減用) |
| prefix (`+N` skip) / suffix 圧縮 | [ZX2 README](https://github.com/einar-saukas/ZX2) "Advanced Features" | ❌ | ❌ | intentional scope (エンコーダ専用機能、ワイヤ形式に影響なし) |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 制御ビットは MSB-first。制御バイトとデータバイトは消費順にインターリーブされる | dzx2.c `read_bit`/`read_byte` | ✅ | `zx2_reference_vector_text` (統合) |
| 2 | インターリーブ Elias gamma: `value=1`、continuation bit 1 のあいだ `value = value*2 + databit`、0 で終端。データビットは非反転 | README / dzx2.c `read_interlaced_elias_gamma` | ✅ | `decode_minimal_literal` + 参照ベクタ全般 |
| 3 | 先頭ブロックは常に literal で indicator bit を持たない | README | ✅ | `zx2_reference_vector_*` (統合) |
| 4 | literal ブロック: `elias(len)` + len バイト | README / compress.c | ✅ | `zx2_reference_vector_text` (統合) |
| 5 | literal 後の bit: 0 = copy-from-last-offset、1 = new-offset | dzx2.c state machine | ✅ | `zx2_reference_vector_rep_offset` (統合) |
| 6 | copy 後の bit: 0 = literal、1 = new-offset | dzx2.c state machine | ✅ | `zx2_reference_vector_mixed` (統合) |
| 7 | copy-from-last-offset: `elias(len)` で前回 offset を再利用 | README | ✅ | `zx2_reference_vector_rep_offset` (統合) |
| 8 | new-offset は専用 1 バイト `255 - offset`。offset ∈ 1..=255 | README / compress.c / dzx2.c | ✅ | `zx2_reference_vector_far_offset` (統合) |
| 9 | offset=0 (バイト `0xff`) は EOF マーカ。EOF 時点で入力を消費しきること (余剰バイトはエラー) | dzx2.c EOF 検証 | ✅ | `zx2_rejects_malformed` (統合) |
| 10 | new-offset の match 長は `elias + 1` (デフォルト min_length=2) | dzx2.c `length = elias+min_length-1` | ✅ | `zx2_reference_vector_*` (統合) |
| 11 | 初期 last_offset = 1 | zx2.h `INITIAL_OFFSET` | ✅ | `zx2_reference_vector_rep_offset` (統合) |
| 12 | エンコード可能な最大 offset は 255 (`MAX_OFFSET_ZX2`) | zx2.c `MAX_OFFSET_ZX2` | ✅ | `zx2_reference_vector_far_offset` (統合: offset=255 の match を含む) |
| 13 | 空入力は空出力に対応 (フォーマット上は空出力を表現不可; crate 内部規約として受理) | crate contract | ✅ | `empty_input` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 14 | 切り詰め制御ビット / リテラル / offset バイトの拒否 | dzx2.c truncated input | ✅ | `rejects_truncated`、`zx2_rejects_malformed` (統合) |
| 15 | match offset が出力済みバイト数を超過する場合は拒否 | dzx2.c `write_bytes` 検証 | ✅ | `rejects_bad_offset` |
| 16 | EOF 後の余剰バイトの拒否 | dzx2.c `input too long` | ✅ | `zx2_rejects_malformed` (統合) |
| 17 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 18 | decode→encode→decode ラウンドトリップ (テキスト / 反復 / バイナリ / offset 上限付近) | README | ✅ | `roundtrip_various`、`zx2_roundtrips` (統合) |
| 19 | エンコーダは greedy 単一候補マッチ探索。参照実装の optimal parsing とは出力が異なる (仕様上正当) | 実装選択 | ✅ | roundtrip で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 20 | CLI `--format zx2` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 ZX2 v1.1 (Einar Saukas) は BSD 3-Clause。本実装は README のフォーマット記述と `dzx2.c` / `compress.c` の動作解析から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `ZX2_*` は参照 C コンプレッサ (ZX2 v1.1) をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証): literal+match 混在、rep-offset、長マッチ連鎖、offset=255 (形式上限) を含む。
- backwards モード (`-b`)、ignore-default-offset (`-z`)、skip-length-increment (`-x`)、limit-block-length (`-y`) はデコーダ側のワイヤ解釈を変えるオプションで、いずれも intentional scope 外。デフォルト forward モードのみ対応。prefix/suffix 圧縮 (圧縮時に外部データを match 参照範囲にするエンコーダ機能) も intentional scope 外で、デコード形式には影響しない。
- ZX2 は ZX1 の minimalist 版で、Z80 デコンプレッサが 48〜56 バイトに収まるよう設計されている (1KB デモ用途)。
- 実装メモ: Elias gamma 値には `1 << 20` の安全性ガードを設けている (無制限増大する malformed 入力の DoS 防止。フォーマット定義ではなく実装追加の制限)。
