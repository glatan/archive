# LZRW1

| 項目 | 内容 |
|------|------|
| 形式概要 | Ross N. Williams の LZRW1 (DCC'91) が使用する圧縮ストリーム。4 バイトの copy flag + グループ列。magic・チェックサムは持たない |
| 基準仕様 | 参照実装 [`lzrw1.c`](https://ftp.funet.fi/pub/misc/compression/lzrw1.c) (Ross N. Williams, public domain、[ross.net/compression](http://www.ross.net/compression/lzrw1.html) / funet ミラー)。lzrw1.c はフォーマット定義節を持たないため、構造は lzrw1-a.c の "DEFINITION OF COMPRESSED FILE FORMAT" 節と lzrw1.c のコード動作から確定 (ローカルスナップショット: `docs/spec/sources/lzrw1.c`) |
| 参照実装 | `lzrw1.c` (Ross N. Williams、public domain、de facto 仕様 + 動作参照 + fixture 生成: `tests/integration/lzrw1.rs` の known-answer ベクター)。詳細: THIRD_PARTY_NOTICES LZRW1 / LZRW2 / LZRW3 / LZRW3-A 項 |
| 実装 | `archive::compress::lzrw1` (decode / decode_bounded / encode)。pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 4 バイトは copy flag。lzrw1-a.c の記述では「残りは 0」だが、lzrw1.c エンコーダは byte0 のみ書き込み byte1-3 は未初期化。デコーダも byte0 のみ評価し byte1-3 を完全に無視 (≠0 でも受理) | lzrw1.c: `FLAG_BYTES 4` + decoder 動作 | ✅ | `decode_copy_flag`、`decode_flag_remainder_bytes_ignored` (byte1-3 ≠0 受理)、`lzrw1_reference_vector_*` (統合) |
| 2 | flag == 1 (FLAG_COPY) の場合、remainder はデータそのまま | lzrw1.c: `FLAG_COPY` | ✅ | `decode_copy_flag`、`decode_verbatim_empty` (remainder 0B) + noise roundtrip、`lzrw1_reference_vector_noise` (統合) |
| 3 | flag == 0 (FLAG_COMPRESS) の場合、remainder は 0 個以上のグループ | lzrw1.c: `FLAG_COMPRESS` | ✅ | `lzrw1_reference_vector_fox` 等 (統合) |
| 4 | 各グループは 2 バイトの control + 最大 16 アイテム。最終グループは 1-16 アイテムでよい | lzrw1.c decoder 動作 | ✅ | `decode_group_boundary_16_items` (17 個目は次グループ)、`lzrw1_reference_vector_*` (統合) |
| 5 | control の bit i が item i に対応 (byte0 = items 0-7、byte1 = items 8-15、各 byte 内は bit0 が先頭アイテム)。0 = literal、1 = copy | lzrw1.c decoder 動作 | ✅ | `decode_control_bit_order` |
| 6 | literal item は 1 バイト | lzrw1.c | ✅ | `decode_literal_group` |
| 7 | copy item は 2 バイト C1 C2。len = `C1 & 0x0f` + 1 (1-16)。LZRW1-A の +3 (3-18) とは非互換 | lzrw1.c decompress 動作: `len=1+(*p_src&0xF)` | ✅ | `decode_copy_item`、`decode_max_len_copy`、`lzrw1_reference_vector_*` (統合) |
| 8 | offset = `(C1 >> 4) * 256 + C2` (1-4095、0 は不使用)。POS-offset からのコピー | lzrw1.c decompress 動作: `offset=(*p_src&0xF0)<<4` (lzrw1-a.c 記法では `C1[4..7]*256+C2`) | ✅ | `decode_max_offset_copy` (offset=4095 受理)、`lzrw1_reference_vector_*` (統合) |
| 9 | 長さ 1-2 の copy item も受理 (参照エンコーダは生成しないがフォーマット上は合法) | lzrw1.c decoder | ✅ | `decode_short_copy` |
| 10 | copy の重複コピー (len > offset) を許容 | lzrw1.c / LZ77 規約 | ✅ | `roundtrip_various` (`[0u8; 2000]`) |
| 11 | 空入力は空出力に対応 | crate contract | ✅ | `empty_input` |
| 12 | flag が 0/1 以外のストリームは拒否 | lzrw1.c | ✅ | `rejects_bad_flag`。参照デコーダは flag≠1 を全て compressed として処理するため、本 reject は参照より厳格な hardening |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 13 | 1-3 バイトの入力 (flag 切り詰め) の拒否。0 バイト入力は空出力として受理 (#11) | lzrw1.c | ✅ | `rejects_truncated_flag` |
| 14 | copy item 途中での入力終端の拒否 | lzrw1.c | ✅ | `rejects_truncated_copy_item`、`lzrw1_rejects_malformed` (統合) |
| 15 | copy offset が 0 または出力済みバイト数超過は拒否 | lzrw1.c | ✅ | `rejects_bad_offset`、`lzrw1_rejects_malformed` (統合) |
| 16 | `decode_bounded` で出力上限を強制 (compressed/verbatim 双方) | crate contract | ✅ | `bounded_decode` |
| 17 | 最終グループが中途半端な位置で終了しても、残り control bit は無視して正常終了 | lzrw1.c decoder 動作 | ✅ | `lzrw1_reference_vector_*` (統合) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 18 | decode→encode→decode ラウンドトリップ | lzrw1.c | ✅ | `roundtrip_various`、`lzrw1_roundtrips` (統合) |
| 19 | 圧縮後サイズが入力 + flag を下回らない場合は verbatim 形式 (flag=1) を出力 | lzrw1.c overrun 経路 | ✅ | noise roundtrip で検証 |
| 20 | エンコーダのマッチ探索は greedy 単一候補ハッシュ (3B プレフィックス、12bit)。40543 乗算の取り出しシフト位置は参照と異なる (TPN 記載済みの意図的差分)。リファレンスとの出力バイト一致は保証しない (参照コード自身が non-deterministic と明記) | lzrw1.c 注記 5 | ✅ | roundtrip + 参照デコーダ相互運用で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 21 | CLI `--format lzrw1` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |
| 22 | ストリーム末尾に control word 未満 (1 バイト) の孤立残りがある場合は無視して受理 | lzrw1.c decoder (`control |= *p_src++ << 8` は領域外読み、参照は UB) | ✅ | 寛容化 — 本実装は安全側として受理。参照デコーダは読み飛ばし。`decode_trailing_orphan_byte` (16 アイテム完了後の孤立 1B) |

## 出典 / 検証メモ

- 参照実装 `lzrw1.c` は public domain (Ross N. Williams, 1991)。本実装はフォーマット構造から書かれた独立実装である。ただし encoder のハッシュ算術 (3 バイト混合式 + 40543 multiplier) は public domain 参照実装由来の定数を共有する (詳細: THIRD_PARTY_NOTICES LZRW 項)。
- 統合テストの `VEC_*` は参照 C 実装をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証)。
- 逆向き (本実装 encode → 参照 C 実装 decode) もローカルで相互運用確認済み。
- 参照コードは「non-deterministic」 (同じ入力でも実行ごとに異なる圧縮表現を出力しうる) と明記しているため、encoder 出力の参照バイト一致は目標にしない。
- LZRW1-A とはフレーミングを共有するが copy item の長さフィールド解釈 (+1 vs +3) が異なり、ワイヤー互換ではない。
