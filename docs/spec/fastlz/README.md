# FastLZ

| 項目 | 内容 |
|------|------|
| 形式概要 | Ariya Hidayat の FastLZ が使用する raw LZ77 ストリーム。コンテナヘッダ・magic・チェックサムを持たない制御バイト列。ストリームは level 1 / level 2 の 2 バリアントを持ち、先頭バイトの bit5 が level-2 マーカーとして機能する |
| 基準仕様 | 参照実装 [`fastlz.c`](https://github.com/ariya/FastLZ) (Ariya Hidayat, MIT license) のフォーマット動作。実装が事実上の規範 (ローカルスナップショット: `docs/spec/sources/fastlz.c`) |
| 参照実装 | `fastlz.c` (MIT、de facto 仕様かつ動作参照。known-answer decode fixture は参照エンコーダで生成)。性能比較 (`docs/bench/`) では固定ソースビルドを使用。詳細: THIRD_PARTY_NOTICES FastLZ 項 |
| 実装 | `archive::compress::fastlz` (decode / decode_bounded / encode / encode_level1 / encode_level2)。pure-Rust 実装 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| level 1 | [`fastlz.c`](https://github.com/ariya/FastLZ) (参照実装、MIT) | ✅ | ✅ | `encode_level1` |
| level 2 | [`fastlz.c`](https://github.com/ariya/FastLZ) (同上) | ✅ | ✅ | 先頭バイト bit5 が L2 マーカー |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭バイトの上位 3bit + 1 が level。level 2 ストリームは先頭バイトの bit5 が立つ (リテラル ctrl の未使用ビットをマーカーとして転用) | fastlz.c: `(*ip++) & 31` / `(5 << 5)` marker | ✅ | `fastlz_reference_vector_l2_marker_and_chain` (統合) |
| 2 | ctrl < 32 はリテラルラン、長さ = ctrl + 1 (1..=32) | fastlz.c | ✅ | `decode_literal_run`、`fastlz_hand_built_segments` (統合) |
| 3 | ctrl >= 32 はマッチ。`ctrl >> 5` in 1..=6 は短形、長さ = field + 2 (3..=8) | fastlz.c: `len = (ctrl >> 5) - 1`, `len + 3` copy | ✅ | `decode_short_match` |
| 4 | `ctrl >> 5` == 7 は長形。level 1 は拡張バイト 1 個、長さ = ext + 9 | fastlz.c level-1 | ✅ | `decode_l1_long_match`、`fastlz_hand_built_segments` (統合) |
| 5 | level 2 の長形拡張は 0xff 連鎖 + 終端バイト、長さ = 9 + 総和 | fastlz.c level-2: `do len += code while code == 255` | ✅ | `decode_l2_ext_chain`、`fastlz_reference_vector_l2_marker_and_chain` (統合) |
| 6 | オフセット = ((ctrl & 0x1f) << 8 \| low)、距離 = offset + 1。level 1 最大 8192、level 2 短形最大 8191 | fastlz.c: `MAX_L1_DISTANCE 8192` / `MAX_L2_DISTANCE 8191` | ✅ | `fastlz_reference_vector_l1_run` / `fastlz_reference_vector_l1_text` (統合) |
| 7 | level 2 で `ctrl & 0x1f == 31` かつ offset-low == 0xff の場合、さらに u16be の距離拡張が続く。距離 = ext16 + 8192 (8192..=73727) | fastlz.c: `code == 255 && ofs == 31<<8` → `ref = op - ofs - MAX_L2_DISTANCE - 1` | ✅ | `decode_l2_far_match`、`fastlz_reference_vector_l2_far_match` (統合) |
| 8 | 拡張長バイトは offset low バイトの前に来る (far match は offset-low の 0xff 後に u16) | fastlz.c | ✅ | `fastlz_reference_vector_l2_far_match` (統合) |
| 9 | match コピーは 1 バイトずつ (重複コピー許容) | fastlz.c / LZ77 系規約 | ✅ | `roundtrip_various` (`[0u8; 1000]` 等) |
| 10 | ストリーム終端 = 入力消費完了。level 1 は残り < 2 バイトで終了 (リファレンス同様末尾 1 バイトを許容)、level 2 は残り 0 で終了。far match の ext16 直前の残存チェックは参照 (3B 要求) より寛容で、ext16 でちょうど終わる入力も受理する | fastlz.c loop condition / `FASTLZ_BOUND_CHECK` | ✅ | 全 roundtrip テスト |
| 11 | 空入力は空ストリームに対応 | crate contract (参照実装は length 0 入力で未定義動作のため規範外) | ✅ | `empty_input` |
| 12 | 先頭バイト上位 3bit が 2 以上 (level 3+) のストリームは拒否 | fastlz.c (未サポート level) | ✅ | `rejects_bad_level` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 13 | 切り詰めリテラルランの拒否 | fastlz.c | ✅ | `rejects_truncated`、`fastlz_rejects_malformed` (統合) |
| 14 | 切り詰め拡張長バイトの拒否 (level 1/2 双方) | fastlz.c | ✅ | `rejects_truncated` |
| 15 | 切り詰めオフセットバイト / far 距離拡張の拒否 | fastlz.c | ✅ | `rejects_truncated`、`fastlz_rejects_malformed` (統合) |
| 16 | match offset > 出力済みバイト数は拒否 | fastlz.c | ✅ | `rejects_offset_before_start`、`fastlz_rejects_malformed` (統合) |
| 17 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 18 | `encode` はリファレンス同様 64 KiB 未満で level 1、以上で level 2 を選択。`encode_level1` / `encode_level2` で明示も可 | fastlz.c: `fastlz_compress` | ✅ | `roundtrip_various` (70000B で level-2 経路) |
| 19 | level 2 エンコーダは距離 >= 8192 のマッチを far 形式で出力 | fastlz.c | ✅ | `decode_l2_far_match` + roundtrip |
| 20 | level 1 エンコーダは 264 バイト超のマッチを連続マッチに分割して出力 (各片は 0 または >=3 の残りを残すよう調整) | fastlz.c: `MAX_LEN 264` | ✅ | `roundtrip_various` (`[0u8; 1000]`) |
| 21 | エンコーダのマッチ探索は greedy 単一候補ハッシュ (3B プレフィックス、15bit ハッシュ。参照の 13bit Knuth 乗算ハッシュとは別構成)。fastlz.c との出力バイト一致は保証しない (仕様上正当なバリエーション) | 実装選択 | ✅ | roundtrip で検証 |
| 23 | encoder の参照実装との差分: L2 far 距離上限 73727 (参照 encoder は < 73725 のみ使用)、L1 距離 <=8192 (参照は <8192)、far match 最小長 3B (参照は dist>=8191 で >=5B)、マッチ延長を入力末尾まで実施 (参照は末尾 ~13B を常に literal)、L1 長 match 分割は decoded 264B 単位 (参照は len_arg 262B 基準)。いずれも wire 上 valid なストリームを生成 | 実装選択 | ✅ | roundtrip + `fastlz_reference_vector_*` で decoder 互換を検証 |
| 24 | fuzz harness (encode/decode/decode_bounded 全経路 + regression 配線) | fuzz/ 構成 | ✅ | `fuzz/src/algorithms.rs` `Algorithm::Fastlz` |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 22 | CLI `--format fastlz` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 `fastlz.c` は MIT ライセンス (Ariya Hidayat)。本実装はフォーマット動作の解析から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `fastlz_reference_vector_*` は参照 C 実装をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証)。L1/L2、0xff 拡張連鎖、far match (距離 12000) を含む。
- FastLZ は RT-RK / WiiUEmu / iOS 系ファームウェア解析等で使われる raw codec であり、コンテナ連携は本モジュールの範囲外。
