# LZRW3-A

| 項目 | 内容 |
|------|------|
| 形式概要 | Ross N. Williams の LZRW3-A (1991) が使用する圧縮ストリーム。LZRW3 の deep-hash 版: hash table の各エントリが 8 候補の partition を持ち、copy item の index は partition 内の位置まで指定する。magic・チェックサムは持たない |
| 基準仕様 | 参照実装 [`lzrw3-a.c`](https://ftp.funet.fi/pub/misc/compression/lzrw3-a.c) (Ross N. Williams, public domain、[ross.net/compression](http://www.ross.net/compression/lzrw3a.html) / funet ミラー) の "DEFINITION OF COMPRESSED FILE FORMAT" 節 + `lzrw3-a.txt` (ローカルスナップショット: `docs/spec/sources/lzrw3-a.c` / `lzrw3-a.txt`) |
| 実装 | `archive::compress::lzrw3a` (decode / decode_bounded / encode)。pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 4 バイトは copy flag。先頭バイトが値を持ち残りは 0 | lzrw3-a.c: `FLAG_BYTES 4` | ✅ | `decode_copy_flag`、`lzrw3a_reference_vector_*` (統合) |
| 2 | flag == 1 (FLAG_COPY) の場合、remainder はデータそのまま | lzrw3-a.c: `FLAG_COPY` | ✅ | `decode_copy_flag` + noise roundtrip、`lzrw3a_reference_vector_noise` (統合) |
| 3 | flag == 0 (FLAG_COMPRESS) の場合、remainder は 0 個以上のグループ | lzrw3-a.c: `FLAG_COMPRESS` | ✅ | `lzrw3a_reference_vector_fox` 等 (統合) |
| 4 | 各グループは 2 バイトの control + 最大 16 アイテム。最終グループは 1-16 アイテムでよい | lzrw3-a.c format 定義 | ✅ | `lzrw3a_reference_vector_*` (統合) |
| 5 | control の bit i が item i に対応。0 = literal、1 = copy | lzrw3-a.c format 定義 | ✅ | `decode_literal_group` |
| 6 | literal item は 1 バイト | lzrw3-a.c | ✅ | `decode_literal_group` |
| 7 | copy item は 2 バイト C1 C2。len = `C1 & 0x0f` + 3 (3-18) | lzrw3-a.c format 定義: `C1[0..3]+3` | ✅ | `decode_copy_after_literals` |
| 8 | index = `(C1 >> 4) * 256 + C2` (0-4095) は deep hash table のエントリ添字。上位側は partition (9bit hash × 8 候補)、下位 3bit は partition 内の候補位置を指す | lzrw3-a.c format 定義 + `DEPTH_BITS 3` / `HASH_BITS 9` | ✅ | `lzrw3a_reference_vector_*` (統合)、deep-hash roundtrip |
| 9 | 各候補エントリは phrase の出力位置のみを保持する。更新対象スロットは全 partition 共有の単一 `cycle` カウンタ (0..DEPTH-1 を巡回する global round-robin; per-entry LRU ではない) で決まる。copy item 処理では参照読み出しが更新より先 | lzrw3-a.c: `UPDATE_P`/`UPDATE_I` マクロの `cycle` | ✅ | `decode_cycle_advances`、roundtrip + 参照ベクタ |
| 10 | literal item は LZRW3 と同様に遅延して hash (3 バイト揃ってから最古の pending を 1 つ処理。copy 到着時に残りを flush) | lzrw3-a.c decoder 動作 | ✅ | literal 連続入力の roundtrip |
| 11 | 全 hash エントリは初期状態で 18 バイト定数文字列 `"123456789012345678"` を指す | lzrw3-a.c: `START_STRING_18`、init | ✅ | `lzrw3a_reference_vector_startstr` (統合) |
| 12 | hash 関数は `((40543 * ((b0<<8) ^ (b1<<4) ^ b2)) >> 4) & 0x1FF` で partition を選択 (LZRW3 の 0xFFF とは mask が異なる) | lzrw3-a.c: `HASH(PTR)` マクロ | ✅ | `lzrw::hash3` (mask=0x1FF) 経由 |
| 13 | 空入力は空出力に対応 | crate contract | ✅ | `empty_input` |
| 14 | flag が 0/1 以外のストリームは拒否 | lzrw3-a.c | ✅ | `rejects_bad_flag` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | 4 バイト未満の入力 (flag 切り詰め) の拒否 | lzrw3-a.c | ✅ | `rejects_truncated_flag` |
| 16 | copy item 途中での入力終端の拒否 | lzrw3-a.c | ✅ | `rejects_truncated_copy_item`、`lzrw3a_rejects_malformed` (統合) |
| 17 | `decode_bounded` で出力上限を強制 (compressed/verbatim 双方) | crate contract | ✅ | `bounded_decode` |
| 18 | 最終グループが中途半端な位置で終了しても、残り control bit は無視して正常終了 | lzrw3-a.c decoder 動作 | ✅ | `lzrw3a_reference_vector_*` (統合) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 19 | decode→encode→decode ラウンドトリップ | lzrw3-a.c | ✅ | `roundtrip_various`、`lzrw3a_roundtrips` (統合) |
| 20 | 圧縮後サイズが入力 + flag を下回らない場合は verbatim 形式 (flag=1) を出力 | lzrw3-a.c overrun 経路 | ✅ | noise roundtrip で検証 |
| 21 | エンコーダはデコーダと同一の deep-hash/cycle 規律 (単一グローバルカウンタの lockstep 再現) を持つ。送信 index が両側で同一 source に解決されることを保証 | lzrw3-a.c compressor 動作 | ✅ | 参照デコーダ相互運用 (167KB 入力) で検証 |
| 22 | リファレンスとの出力バイト一致は保証しない | 実装選択 | ✅ | roundtrip + 参照デコーダ相互運用で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 23 | CLI `--format lzrw3a` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 `lzrw3-a.c` は public domain (Ross N. Williams, 1991)。本実装はフォーマット定義から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `VEC_*` は参照 C 実装をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証)。
- 逆向き (本実装 encode → 参照 C 実装 decode) もローカルで相互運用確認済み (167KB 入力を含む)。
- ワイヤーフォーマット自体は LZRW3 と構造同一だが、index の解釈 (single hash entry vs deep partition + round-robin cycle) が異なるため相互に非互換。なお参照実装の候補置換は per-entry LRU ではなく全 partition 共有の単一 round-robin カウンタである (lzrw3-a.c 中に "LRU" の記述はない)。
