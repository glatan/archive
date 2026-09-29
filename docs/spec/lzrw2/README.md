# LZRW2

| 項目 | 内容 |
|------|------|
| 形式概要 | Ross N. Williams の LZRW2 (1991) が使用する圧縮ストリーム。4 バイトの copy flag + グループ列。copy item は byte offset ではなく phrase table index を格納する。magic・チェックサムは持たない |
| 基準仕様 | 参照実装 [`lzrw2.c`](https://ftp.funet.fi/pub/misc/compression/lzrw2.c) (Ross N. Williams, public domain、[ross.net/compression](http://www.ross.net/compression/lzrw2.html) / funet ミラー) の "DEFINITION OF COMPRESSED FILE FORMAT" 節 + `lzrw2.txt` (ローカルスナップショット: `docs/spec/sources/lzrw2.c` / `lzrw2.txt`) |
| 実装 | `archive::compress::lzrw2` (decode / decode_bounded / encode)。pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 4 バイトは copy flag。先頭バイトが値を持ち残りは 0 | lzrw2.c: `FLAG_BYTES 4` | ✅ | `decode_copy_flag`、`lzrw2_reference_vector_*` (統合) |
| 2 | flag == 1 (FLAG_COPY) の場合、remainder はデータそのまま | lzrw2.c: `FLAG_COPY` | ✅ | `decode_copy_flag` + noise roundtrip、`lzrw2_reference_vector_noise` (統合) |
| 3 | flag == 0 (FLAG_COMPRESS) の場合、remainder は 0 個以上のグループ | lzrw2.c: `FLAG_COMPRESS` | ✅ | `lzrw2_reference_vector_fox` 等 (統合) |
| 4 | 各グループは 2 バイトの control + 最大 16 アイテム。最終グループは 1-16 アイテムでよい | lzrw2.c format 定義 | ✅ | `lzrw2_reference_vector_*` (統合) |
| 5 | control の bit i が item i に対応 (byte0 = items 0-7、byte1 = items 8-15)。0 = literal、1 = copy | lzrw2.c format 定義 | ✅ | `decode_copy_item`、`decode_literal_group` |
| 6 | literal item は 1 バイト | lzrw2.c | ✅ | `decode_literal_group` |
| 7 | copy item は 2 バイト C1 C2。len = `C1 & 0x0f` + 3 (3-18) | lzrw2.c format 定義: `C1[0..3]+3` | ✅ | `decode_copy_item`、`decode_overlapping_copy` |
| 8 | index = `(C1 >> 4) * 256 + C2` (0-4095) は 4096 エントリの巡回 phrase table の添字。OFFSET はテーブル参照で得る | lzrw2.c format 定義: `C1[4..7]*256+C2`、phrase table | ✅ | `decode_phrase_index_semantics`、`lzrw2_reference_vector_*` (統合) |
| 9 | 各アイテム処理後、そのアイテム出力の先頭位置が次の巡回エントリに書き込まれる。copy item では参照エントリの読み出しがテーブル更新より先 | lzrw2.c decoder/encoder 動作 | ✅ | `decode_phrase_index_semantics`、wrap 入力の roundtrip (6000+ items) |
| 10 | phrase table entry 0 は初期状態で 18 バイト定数文字列 `"123456789012345678"` を指す。最初のアイテムで上書きされるまでは index 0 はその文字列を参照 | lzrw2.c: `START_STRING_18`、dummy entry | ✅ | `decode_start_string_reference`、`lzrw2_reference_vector_startstr` (統合) |
| 11 | 未書き込みの phrase エントリへの index 参照は拒否 | crate contract (参照実装は未初期化参照で UB) | ✅ | `rejects_unwritten_phrase_index`、`lzrw2_rejects_malformed` (統合) |
| 12 | 空入力は空出力に対応 | crate contract | ✅ | `empty_input` |
| 13 | flag が 0/1 以外のストリームは拒否 | lzrw2.c | ✅ | `rejects_bad_flag` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 14 | 4 バイト未満の入力 (flag 切り詰め) の拒否 | lzrw2.c | ✅ | `rejects_truncated_flag` |
| 15 | copy item 途中での入力終端の拒否 | lzrw2.c | ✅ | `rejects_truncated_copy_item`、`lzrw2_rejects_malformed` (統合) |
| 16 | `decode_bounded` で出力上限を強制 (compressed/verbatim 双方) | crate contract | ✅ | `bounded_decode` |
| 17 | 最終グループが中途半端な位置で終了しても、残り control bit は無視して正常終了 | lzrw2.c decoder 動作 | ✅ | `lzrw2_reference_vector_*` (統合) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 18 | decode→encode→decode ラウンドトリップ | lzrw2.c | ✅ | `roundtrip_various`、`lzrw2_roundtrips` (統合) |
| 19 | 圧縮後サイズが入力 + flag を下回らない場合は verbatim 形式 (flag=1) を出力 (参照実装は flag 込み出力が `src_len` を超えた時点で中断する能動ガード; 本実装は圧縮完了後に `out.len() >= FLAG_BYTES + src_len` で事後判定するため、verbatim 判定の閾値は最大 FLAG_BYTES (4 バイト) だけ後ろ倒しになりうる) | lzrw2.c overrun 経路 | ✅ | noise roundtrip で検証 |
| 20 | エンコーダはデコーダと同一の phrase table 規律 (各アイテムで次エントリ更新、hash table は phrase index を保持) を再現。送信 index が両側で同一 source に解決されることを保証 | lzrw2.c compressor 動作 | ✅ | 参照デコーダ相互運用 (167KB 入力) で検証 |
| 21 | リファレンスとの出力バイト一致は保証しない (hash 関数・候補選択はフォーマット定義外のため、本実装は参照と同一式 `HASH(PTR)` を採用しつつも選択枝は異なりうる) | 実装選択 | ✅ | roundtrip + 参照デコーダ相互運用で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 22 | CLI `--format lzrw2` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 `lzrw2.c` は public domain (Ross N. Williams, 1991)。本実装はフォーマット定義から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `VEC_*` は参照 C 実装をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証)。
- 逆向き (本実装 encode → 参照 C 実装 decode) もローカルで相互運用確認済み (phrase table wrap を越える 167KB 入力を含む)。
- 参照実装は phrase table 未書き込みエントリを参照した場合に未定義メモリを読む。本実装はこれを明示エラーにする。
