# ZX5

| 項目 | 内容 |
|------|------|
| 形式概要 | Einar Saukas の ZX5 が使用する raw LZ77 ストリーム。ZX0 から派生し、copy-from-2nd-last-offset / copy-from-3rd-last-offset の 2 ブロック型を追加した形式。制御ビット列とデータバイトがインターリーブする。magic・コンテナヘッダ・チェックサムは持たない |
| 基準仕様 | [ZX5 README](https://github.com/einar-saukas/ZX5) "File Format" (ローカルスナップショット: `docs/spec/sources/zx5_README_v2.0.md`) + 参照実装 `dzx5.c` / `compress.c` (Einar Saukas, BSD 3-Clause) |
| 実装 | `archive::compress::zx5` (decode / decode_bounded / encode)。pure-Rust 実装 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| v2 forward / inverted offset-MSB | [ZX5 README](https://github.com/einar-saukas/ZX5) + `dzx5.c` (BSD-3) | ✅ | ✅ | |
| classic v1 (`-c`) | [ZX5 README](https://github.com/einar-saukas/ZX5) | ❌ | ❌ | intentional scope (offset-MSB elias 非反転) |
| backwards (`-b`) | [ZX5 README](https://github.com/einar-saukas/ZX5) | ❌ | ❌ | intentional scope |
| quick (`-q`, ZX7 offset 制限) | [ZX5 README](https://github.com/einar-saukas/ZX5) | ❌ | ❌ | intentional scope (エンコード側のみ、offset<=2176) |
| prefix (`+N` skip) / suffix 圧縮 | [ZX5 README](https://github.com/einar-saukas/ZX5) "Advanced Features" | ❌ | ❌ | intentional scope (エンコーダ専用機能、ワイヤ形式に影響なし) |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 制御ビットは MSB-first。制御バイトとデータバイトは消費順にインターリーブされる | dzx5.c `read_bit`/`read_byte` | ✅ | `zx5_reference_vector_text` (統合) |
| 2 | インターリーブ Elias gamma: `value=1`、continuation bit 0 のあいだ `value = value*2 + databit`、1 で終端 | README / dzx5.c `read_interlaced_elias_gamma` | ✅ | `decode_minimal_literal` + 参照ベクタ全般 |
| 3 | literal / copy-last / prev-offset 長の elias データビットは非反転、new-offset の offset-MSB elias は v2 で反転 | README / compress.c `invert_mode` | ✅ | `zx5_reference_vector_*` (統合) |
| 4 | 先頭ブロックは常に literal で indicator bit を持たない | README | ✅ | `zx5_reference_vector_*` (統合) |
| 5 | literal ブロック: `elias(len)` + len バイト | README / compress.c | ✅ | `zx5_reference_vector_text` (統合) |
| 6 | literal 後の bit: 0 = copy-from-last-offset、1 = other-offsets 群 | dzx5.c state machine | ✅ | `zx5_reference_vector_rep_offset` (統合) |
| 7 | copy 後の bit: 0 = literal、1 = other-offsets 群 | dzx5.c state machine | ✅ | `zx5_reference_vector_mixed` (統合) |
| 8 | copy-from-last-offset: `elias(len)` で前回 offset を再利用 | README | ✅ | `zx5_reference_vector_rep_offset` (統合) |
| 9 | other-offsets 群の先頭 bit: 0 = prev-offset (2nd/3rd last)、1 = new-offset | README / dzx5.c | ✅ | `zx5_reference_vector_alt_offsets` (統合) |
| 10 | prev-offset の次 bit: 0 = 2nd last (last1↔last2 ローテート)、1 = 3rd last (last3→last1 に降順シフト)。その後 `elias(len)` | README / dzx5.c | ✅ | `zx5_reference_vector_alt_offsets` (統合) |
| 11 | new-offset: `*` bit (後続 `elias(len-1)` の先頭ビット) → `elias(MSB+1)` (v2 反転) → LSB 1 バイト。decode: `offset = msb*256 - byte` | README / dzx5.c `ahead_bit`/`backtrack` / compress.c | ✅ | `zx5_reference_vector_*` (統合) |
| 12 | offset MSB=256 は EOF マーカ。EOF 時点で入力を消費しきること (余剰バイトはエラー) | dzx5.c EOF 検証 | ✅ | `zx5_rejects_malformed` (統合) |
| 13 | new-offset の match 長は `elias + 1` (最小 2 バイト) | dzx5.c `length = elias+1` | ✅ | `zx5_reference_vector_*` (統合) |
| 14 | 初期 last_offset1 = 1、last_offset2/3 = 0 (offset=0 の prev-offset コピーは無効として拒否) | zx5.h `INITIAL_OFFSET` / dzx5.c | ✅ | `zx5_reference_vector_rep_offset` (統合)、`rejects_zero_prev_offset` |
| 15 | エンコード可能な最大 offset は 65280 (`MAX_OFFSET_ZX5`) | zx5.c `MAX_OFFSET_ZX5` | ✅ | `decode_far_offset`、エンコーダ側で上限内のみ出力 |
| 16 | 空入力は空出力に対応 (フォーマット上は空出力を表現不可; crate 内部規約として受理) | crate contract | ✅ | `empty_input` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 17 | 切り詰め制御ビット / リテラル / LSB バイトの拒否 | dzx5.c truncated input | ✅ | `rejects_truncated`、`zx5_rejects_malformed` (統合) |
| 18 | match offset が出力済みバイト数を超過する場合は拒否 | dzx5.c `write_bytes` 検証 | ✅ | `rejects_bad_offset` |
| 19 | EOF 後の余剰バイトの拒否 | dzx5.c `input too long` | ✅ | `zx5_rejects_malformed` (統合) |
| 20 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 21 | decode→encode→decode ラウンドトリップ (テキスト / 反復 / バイナリ / 複数 offset 交互 / far offset) | README | ✅ | `roundtrip_various`、`zx5_roundtrips` (統合) |
| 22 | エンコーダは greedy 単一候補マッチ探索。参照実装の optimal parsing とは出力が異なる (仕様上正当) | 実装選択 | ✅ | roundtrip で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 23 | CLI `--format zx5` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 ZX5 v2.0 (Einar Saukas) は BSD 3-Clause。本実装は README のフォーマット記述と `dzx5.c` / `compress.c` の動作解析から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `ZX5_*` は参照 C コンプレッサ (ZX5 v2.0) をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証): literal+match 混在、rep-offset、長マッチ連鎖、2nd/3rd-last offset、マルチビット offset MSB を含む。
- backwards モード (`-b`)、classic v1 形式 (`-c`、非反転 offset-MSB)、quick モード (`-q`、エンコード時 offset <=2176 の制限) は intentional scope 外。v2 forward / inverted offset-MSB のみ対応。prefix/suffix 圧縮 (圧縮時に外部データを match 参照範囲にするエンコーダ機能) も intentional scope 外で、デコード形式には影響しない。
- ZX5 は ZX0 の派生で 5 ブロック型を持つが、作者自身が「compressor is very much slower and consumes too much memory therefore it's not very practical」「highly recommended to use ZX0 instead」と明記する experimental 形式。
- 実装メモ: Elias gamma 値には `1 << 20` の安全性ガードを設けている (無制限増大する malformed 入力の DoS 防止。フォーマット定義ではなく実装追加の制限)。
