# LZRW3

| 項目 | 内容 |
|------|------|
| 形式概要 | Ross N. Williams の LZRW3 (1991) が使用する圧縮ストリーム。4 バイトの copy flag + グループ列。copy item は byte offset ではなく hash table index を格納し、decompressor も同一の hash table を維持する。magic・チェックサムは持たない |
| 基準仕様 | 参照実装 [`lzrw3.c`](https://ftp.funet.fi/pub/misc/compression/lzrw3.c) (Ross N. Williams, public domain、[ross.net/compression](http://www.ross.net/compression/lzrw3.html) / funet ミラー) の "DEFINITION OF COMPRESSED FILE FORMAT" 節 + `lzrw3.txt` (ローカルスナップショット: `docs/spec/sources/lzrw3.c` / `lzrw3.txt`) |
| 実装 | `archive::compress::lzrw3` (decode / decode_bounded / encode)。pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 4 バイトは copy flag。先頭バイトが値を持ち残りは 0 | lzrw3.c: `FLAG_BYTES 4` | ✅ | `decode_copy_flag`、`lzrw3_reference_vector_*` (統合) |
| 2 | flag == 1 (FLAG_COPY) の場合、remainder はデータそのまま | lzrw3.c: `FLAG_COPY` | ✅ | `decode_copy_flag` + noise roundtrip、`lzrw3_reference_vector_noise` (統合) |
| 3 | flag == 0 (FLAG_COMPRESS) の場合、remainder は 0 個以上のグループ | lzrw3.c: `FLAG_COMPRESS` | ✅ | `lzrw3_reference_vector_fox` 等 (統合) |
| 4 | 各グループは 2 バイトの control + 最大 16 アイテム。最終グループは 1-16 アイテムでよい | lzrw3.c format 定義 | ✅ | `lzrw3_reference_vector_*` (統合) |
| 5 | control の bit i が item i に対応。0 = literal、1 = copy | lzrw3.c format 定義 | ✅ | `decode_literal_group`、`decode_copy_after_literals` |
| 6 | literal item は 1 バイト | lzrw3.c | ✅ | `decode_literal_group` |
| 7 | copy item は 2 バイト C1 C2。len = `C1 & 0x0f` + 3 (3-18) | lzrw3.c format 定義: `C1[0..3]+3` | ✅ | `decode_copy_after_literals` |
| 8 | index = `(C1 >> 4) * 256 + C2` (0-4095) は 4096 エントリ hash table の添字。エントリは直近 phrase の出力位置を保持し、copy source を与える | lzrw3.c format 定義: `C1[4..7]*256+C2` | ✅ | `decode_copy_after_literals`、`lzrw3_reference_vector_*` (統合) |
| 9 | copy item 処理では参照エントリの読み出しがテーブル更新より先。更新では当該アイテムの出力開始位置を同じ index に書き込む | lzrw3.c decoder/encoder 動作 | ✅ | `decode_copy_after_literals` |
| 10 | literal item は即座に hash できないため、テーブル更新は遅延: 連続 literal が 3 バイト揃った時点で最古の 1 つを hash。copy item 到着時に残りの pending literal を先に flush してから copy エントリを更新 | lzrw3.c: `literal_bytes` 追跡ロジック | ✅ | `decode_deferred_literal_hash`、literal 連続入力の roundtrip |
| 11 | 全 hash エントリは初期状態で 18 バイト定数文字列 `"123456789012345678"` を指す (参照実装は全エントリを dummy pointer で初期化)。よって任意の index は常に解決可能 | lzrw3.c: `START_STRING_18`、init | ✅ | `decode_start_string_reference`、`lzrw3_reference_vector_startstr` (統合) |
| 12 | hash 関数は `((40543 * ((b0<<8) ^ (b1<<4) ^ b2)) >> 4) & 0xFFF` を compressor/decompressor で共有 | lzrw3.c: `HASH(PTR)` マクロ | ✅ | `lzrw::hash3` 経由、`decode_copy_after_literals` |
| 13 | 空入力は空出力に対応 | crate contract | ✅ | `empty_input` |
| 14 | flag が 0/1 以外のストリームは拒否 | lzrw3.c | ✅ | `rejects_bad_flag` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | 4 バイト未満の入力 (flag 切り詰め) の拒否 | lzrw3.c | ✅ | `rejects_truncated_flag` |
| 16 | copy item 途中での入力終端の拒否 | lzrw3.c | ✅ | `rejects_truncated_copy_item`、`lzrw3_rejects_malformed` (統合) |
| 17 | `decode_bounded` で出力上限を強制 (compressed/verbatim 双方) | crate contract | ✅ | `bounded_decode` |
| 18 | 最終グループが中途半端な位置で終了しても、残り control bit は無視して正常終了 | lzrw3.c decoder 動作 | ✅ | `lzrw3_reference_vector_*` (統合) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 19 | decode→encode→decode ラウンドトリップ | lzrw3.c | ✅ | `roundtrip_various`、`lzrw3_roundtrips` (統合) |
| 20 | 圧縮後サイズが入力 + flag を下回らない場合は verbatim 形式 (flag=1) を出力 | lzrw3.c overrun 経路 | ✅ | noise roundtrip で検証 |
| 21 | エンコーダはデコーダと同一のテーブル規律 (遅延 literal hash 含む) を再現。送信 index が両側で同一 source に解決されることを保証 | lzrw3.c compressor 動作 | ✅ | 参照デコーダ相互運用 (167KB 入力) で検証 |
| 22 | リファレンスとの出力バイト一致は保証しない | 実装選択 | ✅ | roundtrip + 参照デコーダ相互運用で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 23 | CLI `--format lzrw3` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 `lzrw3.c` は public domain (Ross N. Williams, 1991)。本実装はフォーマット定義から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `VEC_*` は参照 C 実装をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証)。
- 逆向き (本実装 encode → 参照 C 実装 decode) もローカルで相互運用確認済み (167KB 入力を含む)。
- LZRW3 のワイヤーフォーマットは LZRW2 と構造同一だが、copy item の index が phrase table ではなく hash table を指す点で意味論が異なり、相互に非互換。
