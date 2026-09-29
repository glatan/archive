# ZX1

| 項目 | 内容 |
|------|------|
| 形式概要 | Einar Saukas の ZX1 が使用する raw LZ77 ストリーム。ZX0 から派生した形式で、制御ビット列とデータバイトがインターリーブする。ZX0 との差分は Elias 符号の継続ビット反転 (ZX1 では `1` が継続) とオフセット表現 (ZX1 は 1〜2 バイトの反転格納)。magic・コンテナヘッダ・チェックサムは持たない |
| 基準仕様 | [ZX1 README](https://github.com/einar-saukas/ZX1) "File Format" (ローカルスナップショット: `docs/spec/sources/zx1_README.md`) + 参照実装 `dzx1.c` / `zx1.c` (Einar Saukas, BSD 3-Clause) |
| 実装 | `archive::compress::zx1` (decode / decode_bounded / encode)。pure-Rust 実装 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| forward / non-inverted | [ZX1 README](https://github.com/einar-saukas/ZX1) + `dzx1.c` (BSD-3) | ✅ | ✅ | |
| backwards (`-b`) | [ZX1 README](https://github.com/einar-saukas/ZX1) | ❌ | ❌ | intentional scope |
| prefix (`+N` skip) / suffix 圧縮 | [ZX1 README](https://github.com/einar-saukas/ZX1) "Advanced Features" | ✅ | ❌ | `decode_with_prefix` で外部履歴を前置。suffix 圧縮はエンコーダ側概念のため対象外 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 制御ビットは MSB-first。制御バイトとデータバイトは消費順にインターリーブされる | dzx1.c `read_bit`/`read_byte` | ✅ | `zx1_reference_vector_text` (統合) |
| 2 | インターリーブ Elias gamma: `value=1`、continuation bit 1 のあいだ `value = value*2 + databit`、0 で終端。データビットは非反転 | README / dzx1.c `read_interlaced_elias_gamma` | ✅ | `decode_minimal_literal` + 参照ベクタ全般 |
| 3 | 先頭ブロックは常に literal で indicator bit を持たない | README | ✅ | `zx1_reference_vector_*` (統合) |
| 4 | literal ブロック: `elias(len)` + len バイト | README / zx1.c | ✅ | `zx1_reference_vector_text` (統合) |
| 5 | literal 後の bit: 0 = copy-from-last-offset、1 = new-offset | dzx1.c state machine | ✅ | `zx1_reference_vector_rep_offset` (統合) |
| 6 | copy 後の bit: 0 = literal、1 = new-offset | dzx1.c state machine | ✅ | `zx1_reference_vector_mixed` (統合) |
| 7 | copy-from-last-offset: `elias(len)` で前回 offset を再利用 | README | ✅ | `zx1_reference_vector_rep_offset` (統合) |
| 8 | new-offset は 1〜2 バイト。先頭バイトが偶数なら 1 バイト形式で `offset = 128 - v/2` (距離 ≤128) | README / dzx1.c | ✅ | `zx1_reference_vector_text` (統合) |
| 9 | 先頭バイトが奇数なら 2 バイト形式。第 2 バイト `i` を読み `offset = 32512 - (i&254)*128 - (v&254) - (i&1)` | README / dzx1.c | ✅ | `zx1_reference_vector_far_offset` (統合) |
| 10 | 算出 offset ≤ 0 は EOF マーカ。EOF 時点で入力を消費しきること (余剰バイトはエラー) | dzx1.c EOF 検証 | ✅ | `zx1_rejects_malformed` (統合) |
| 11 | new-offset の match 長は `elias + 1` (最小 2 バイト) | dzx1.c `length = elias + 1` | ✅ | `zx1_reference_vector_*` (統合) |
| 12 | 初期 last_offset = 1 | zx1.h `INITIAL_OFFSET` | ✅ | `zx1_reference_vector_rep_offset` (統合) |
| 13 | エンコード可能な最大 offset は 32512 (`MAX_OFFSET`) | zx1.h `MAX_OFFSET` | ✅ | `decode_far_offset`、エンコーダ側で上限内のみ出力 |
| 14 | 空入力は空出力に対応 (フォーマット上は空出力を表現不可; crate 内部規約として受理) | crate contract | ✅ | `empty_input` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | 切り詰め制御ビット / リテラル / offset バイトの拒否 | dzx1.c truncated input | ✅ | `rejects_truncated`、`zx1_rejects_malformed` (統合) |
| 16 | match offset が出力済みバイト数を超過する場合は拒否 | dzx1.c 検証 | ✅ | `rejects_bad_offset` |
| 17 | EOF 後の余剰バイトの拒否 | dzx1.c `input too long` | ✅ | `zx1_rejects_malformed` (統合) |
| 18 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 19 | decode→encode→decode ラウンドトリップ (テキスト / 反復 / バイナリ / far offset) | README | ✅ | `roundtrip_various`、`zx1_roundtrips` (統合) |
| 20 | エンコーダは greedy 単一候補マッチ探索。参照実装の optimal parsing とは出力が異なる (仕様上正当) | 実装選択 | ✅ | roundtrip で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 21 | CLI `--format zx1` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 ZX1 v1.5 (Einar Saukas) は BSD 3-Clause。本実装は README のフォーマット記述と `dzx1.c` の動作解析から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `ZX1_*` は参照 C コンプレッサ (ZX1 v1.5) をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証): literal+match 混在、rep-offset、長マッチ連鎖、2 バイト offset 形式を含む。
- backwards モード (`-b`、後方読み) は intentional scope 外。prefix decode は `decode_with_prefix` で対応済み (suffix 圧縮はエンコーダ側概念のため対象外)。
- ZX1 は ZX Spectrum 等のレトロプラットフォーム向けに設計された codec で、ZX0 より伸張コードが小さい代わりに圧縮率がわずかに劣る設計。
- 実装メモ: Elias gamma 値には `1 << 20` の安全性ガードを設けている (無制限増大する malformed 入力の DoS 防止。フォーマット定義ではなく実装追加の制限)。
