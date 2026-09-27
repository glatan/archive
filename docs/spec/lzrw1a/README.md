# LZRW1-A

| 項目 | 内容 |
|------|------|
| 形式概要 | Ross N. Williams の LZRW1-A (1991) が使用する圧縮ストリーム。4 バイトの copy flag + グループ列。magic・チェックサムは持たない |
| 基準仕様 | 参照実装 [`lzrw1-a.c`](https://ftp.funet.fi/pub/misc/compression/lzrw1-a.c) (Ross N. Williams, public domain、[ross.net/compression](http://www.ross.net/compression/lzrw1a.html) / funet ミラー) の "DEFINITION OF COMPRESSED FILE FORMAT" 節 (ローカルスナップショット: `docs/spec/sources/lzrw1-a.c` / `lzrw1-a.txt`) |
| 実装 | `archive::compress::lzrw1a` (decode / decode_bounded / encode)。pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 4 バイトは copy flag。先頭バイトが値を持ち残りは 0 | lzrw1-a.c: `FLAG_BYTES 4` | ✅ | `decode_copy_flag`、`lzrw1a_reference_vector_verbatim` (統合) |
| 2 | flag == 1 (FLAG_COPY) の場合、remainder はデータそのまま | lzrw1-a.c: `FLAG_COPY` | ✅ | `decode_copy_flag` + noise roundtrip |
| 3 | flag == 0 (FLAG_COMPRESS) の場合、remainder は 0 個以上のグループ | lzrw1-a.c: `FLAG_COMPRESS` | ✅ | `lzrw1a_reference_vector_compressed` (統合) |
| 4 | 各グループは 2 バイトの control + 最大 16 アイテム。最終グループは 1-16 アイテムでよい | lzrw1-a.c format 定義 | ✅ | `lzrw1a_reference_vector_compressed` (統合) |
| 5 | control の bit i が item i に対応 (byte0 = items 0-7、byte1 = items 8-15、各 byte 内は bit0 が先頭アイテム)。0 = literal、1 = copy | lzrw1-a.c format 定義 | ✅ | `decode_control_bit_order` |
| 6 | literal item は 1 バイト | lzrw1-a.c | ✅ | `decode_literal_group` |
| 7 | copy item は 2 バイト C1 C2。len = `C1 & 0x0f` + 3 (3-18) | lzrw1-a.c: `C1[0..3]+3` | ✅ | `decode_copy_item` |
| 8 | offset = `(C1 >> 4) * 256 + C2` (1-4095、0 は不使用)。POS-offset からのコピー | lzrw1-a.c: `C1[4..7]*256+C2` | ✅ | `lzrw1a_reference_vector_max_offset` (統合、offset 4095 / len 18 を含む) |
| 9 | copy の重複コピー (len > offset) を許容 | lzrw1-a.c / LZ77 規約 | ✅ | `roundtrip_various` (`[0u8; 2000]`) |
| 10 | 空入力は空出力に対応 | crate contract | ✅ | `empty_input` |
| 11 | flag が 0/1 以外のストリームは拒否 | lzrw1-a.c | ✅ | `rejects_bad_flag` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 12 | 4 バイト未満の入力 (flag 切り詰め) の拒否 | lzrw1-a.c | ✅ | `rejects_truncated_flag` |
| 13 | copy item 途中での入力終端の拒否 | lzrw1-a.c | ✅ | `rejects_truncated_copy_item`、`lzrw1a_rejects_malformed` (統合) |
| 14 | copy offset が 0 または出力済みバイト数超過は拒否 | lzrw1-a.c | ✅ | `rejects_bad_offset`、`lzrw1a_rejects_malformed` (統合) |
| 15 | `decode_bounded` で出力上限を強制 (compressed/verbatim 双方) | crate contract | ✅ | `bounded_decode` |
| 16 | 最終グループが中途半端な位置で終了しても、残り control bit は無視して正常終了 | lzrw1-a.c デコーダ動作 | ✅ | `lzrw1a_reference_vector_compressed` (統合) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 17 | decode→encode→decode ラウンドトリップ | lzrw1-a.c | ✅ | `roundtrip_various`、`lzrw1a_roundtrips` (統合) |
| 18 | 圧縮後サイズが入力 + flag を下回らない場合は verbatim 形式 (flag=1) を出力 | lzrw1-a.c overrun 経路 | ✅ | noise roundtrip で検証 |
| 19 | エンコーダのマッチ探索は greedy 単一候補ハッシュ (3B プレフィックス、12bit)。リファレンスとの出力バイト一致は保証しない | 実装選択 | ✅ | roundtrip で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 20 | CLI `--format lzrw1a` で decode/encode (magic がないため自動検出なし) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 参照実装 `lzrw1-a.c` は public domain (Ross N. Williams, 1991)。本実装は同ファイルのフォーマット定義から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `VEC_*` は参照 C 実装をローカルでコンパイルして生成した既知解答ベクタ (decode のみ検証): verbatim 形式、通常圧縮、len 18 / offset 4095 の最大値コピーを含む。
- 参考: LZRW1-A には「最終アイテムが長さ 17-18 の copy item の場合に発生するバグ」が 68000 版で報告されたという言及が歴史的資料に存在する (ただしピン留めした lzrw1-a.c / lzrw1-a.txt には該当記述がなく、本リポジトリでは未検証)。本実装はそのバグを再現せず、フォーマット定義どおり正しくデコードする。
- LZRW1-A は復号側でランダムアクセス可能な生コーデックであり、Amiga の XPK 等で使われた実績がある。コンテナ連携は本モジュールの範囲外。
