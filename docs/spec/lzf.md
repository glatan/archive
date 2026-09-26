# LZF (liblzf)

| 項目 | 内容 |
|------|------|
| 形式概要 | Marc Lehmann の liblzf が使用する raw LZ77 ストリーム。コンテナヘッダ・magic・チェックサムを持たない制御バイト列 |
| 基準仕様 | liblzf ソース内フォーマット記述 (`lzfP.h` / `lzf_c.c`、Marc Alexander Lehmann、BSD license) + ning/compress `LZFFormat` ドキュメント |
| 実装 | `archive::compress::lzf` (decode / decode_bounded / encode)。仕様記述からの pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | ctrl < 32 はリテラルラン、長さ = ctrl + 1 (1..=32) | lzfP.h: `000LLLLL <L+1>` | ✅ | `decode_literal_run`、`lzf_hand_built_literal_run` (統合) |
| 2 | ctrl >= 32 はマッチ。`ctrl >> 5` in 1..=6 は 2B 形、長さ = n + 2 (3..=8) | lzfP.h: `LLLooooo oooooooo` | ✅ | `decode_short_match`、`lzf_hand_built_matches` (統合) |
| 3 | `ctrl >> 5` == 7 は 3B 形: 拡張バイトが続き、長さ = ext + 9 (9..=264) | lzfP.h: `111ooooo LLLLLLLL oooooooo` | ✅ | `decode_long_match`、`lzf_hand_built_matches` (統合) |
| 4 | オフセット = ((ctrl & 0x1f) << 8 \| low)、距離 = offset + 1 (1..=8192) | lzfP.h: `o+1=1..4096` / LZFFormat (実際の最大は 13bit = 8192) | ✅ | `decode_offset_high_bits` |
| 5 | 拡張長バイトは offset low バイトの前に来る (LLLLLLLL 後に oooooooo) | lzfP.h: `111ooooo LLLLLLLL oooooooo` | ✅ | `lzf_hand_built_matches` (統合) |
| 6 | match コピーは 1 バイトずつ (重複コピー許容) | lzfP.h / LZ77 系規約 | ✅ | `roundtrip_various` (`[0u8; 1000]` 等) |
| 7 | ストリーム終端 = 入力消費完了 (明示的終端記号なし) | lzfP.h | ✅ | 全 roundtrip テスト |
| 8 | 空入力は空ストリームに対応 | lzfP.h | ✅ | `roundtrip_various` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 9 | 切り詰めリテラルランの拒否 | lzfP.h | ✅ | `rejects_truncated`、`lzf_rejects_malformed` (統合) |
| 10 | 切り詰め拡張長バイトの拒否 | lzfP.h | ✅ | `rejects_truncated` |
| 11 | 切り詰めオフセットバイトの拒否 | lzfP.h | ✅ | `rejects_truncated`、`lzf_rejects_malformed` (統合) |
| 12 | match offset > 出力済みバイト数は拒否 | lzfP.h | ✅ | `rejects_offset_before_start`、`lzf_rejects_malformed` (統合) |
| 13 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode`、`lzf_roundtrip_text_and_binary` (統合) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 14 | decode→encode→decode ラウンドトリップ (空 / 短い / 反復 / バイナリ大) | lzfP.h | ✅ | `roundtrip_various`、`lzf_roundtrip_text_and_binary` (統合) |
| 15 | リテラルランは 32 バイト以下の制御バイト単位に分割 | lzfP.h: `000LLLLL` | ✅ | `lzf_hand_built_literal_run` (統合) + roundtrip |
| 16 | マッチ長 9 以上は拡張バイト形式を使用 | lzfP.h | ✅ | `decode_long_match` + roundtrip |
| 17 | エンコーダのマッチ探索は greedy 単一候補ハッシュ (3B プレフィックス)。liblzf との出力バイト一致は保証しない (仕様上正当なバリエーション) | 実装選択 | ✅ | roundtrip で検証 |
| 18 | エンコーダは常に LZF ストリームを出力 (非圧縮フォールバックなし — 形式が複合しないため常に正当) | lzfP.h | ✅ | `roundtrip_various` |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 19 | CLI `--format lzf` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |
| 20 | fuzz algorithm `lzf` (roundtrip + regression template) | crate fuzz contract | ✅ | fuzz 登録 |

## 出典 / 検証メモ

- 参照実装 liblzf は BSD ライセンス。本実装はフォーマット記述 (lzfP.h コメント、LZFFormat wiki) から書かれた独立実装であり、コードの移植は行っていない。
- LZF ストリームは HDF5 `lzf` フィルタ等で chunk 単位で使われる raw codec であり、コンテナ連携は本モジュールの範囲外。
