# MS-XCA (Xpress / Xpress Huffman / LZNT1)

| 項目 | 内容 |
|------|------|
| 形式概要 | Microsoft Xpress Compression Algorithms の 3 バリアント: Plain LZ77 ("Xpress", `COMPRESSION_FORMAT_XPRESS`)、LZ77+Huffman ("Xpress Huffman", `COMPRESSION_FORMAT_XPRESS_HUFF`)、LZNT1 (`COMPRESSION_FORMAT_LZNT1`) |
| 基準仕様 | [MS-XCA] Xpress Compression Algorithm (Microsoft Open Specifications, <https://learn.microsoft.com/openspecs/windows_protocols/ms-xca/>、rev 10.0 版固定 PDF: <https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-XCA/%5bMS-XCA%5d-240423.pdf>。ローカルスナップショット: `docs/spec/sources/ms-xca_10.0_240423.pdf`)。**監査メモ: この PDF は保護付きでテキスト抽出不可のため、spec↔コード突合は実装内コメント・既存 spec 記述の相互確認にとどまる。仕様書側の全要件網羅は未検証** |
| 実装 | `archive::compress::xca::{lz77, huffman, lznt1}`。仕様書のみからの pure-Rust 実装。サードパーティコードの移植なし |

MS-XCA のストリームはコンテナヘッダや magic を持たない生コーデック列であり、
API/CLI での利用には形式の明示が必要 (`--format xpress` / `xpress-huff` / `lznt1`)。

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| Plain LZ77 (`COMPRESSION_FORMAT_XPRESS`) | [MS-XCA](https://learn.microsoft.com/openspecs/windows_protocols/ms-xca/) | ✅ | ✅ | |
| LZ77+Huffman (`COMPRESSION_FORMAT_XPRESS_HUFF`) | [MS-XCA](https://learn.microsoft.com/openspecs/windows_protocols/ms-xca/) | ✅ | ✅ | |
| LZNT1 (`COMPRESSION_FORMAT_LZNT1`) | [MS-XCA](https://learn.microsoft.com/openspecs/windows_protocols/ms-xca/) | ✅ | ✅ | |

## Plain LZ77 (Xpress)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 32-bit LE flag word が 32 要素を MSB 順に記述 | [MS-XCA] §2.3 / §2.4 | ✅ | `spec_example_literals` |
| 2 | flag=0 は 1 バイトリテラル | [MS-XCA] §2.4 | ✅ | `spec_example_literals` |
| 3 | flag=1 は 16-bit match word (上位 13bit: offset-1、下位 3bit: length-3) | [MS-XCA] §2.3 | ✅ | `spec_example_match` |
| 4 | length フィールド 7 は拡張長: 連続 2 マッチで nibble byte を共有 | [MS-XCA] §2.3 | ✅ | `xpress_windows_vector_shared_nibble` (統合) |
| 5 | nibble 15 → byte、byte 255 → u16、u16 0 → u32 の多段拡張長 | [MS-XCA] §2.3 | ✅ | `long_match_u16_escape`、encode 側同経路 |
| 6 | u16 拡張長が 15+7 未満は不正として拒否 | [MS-XCA] §2.4 | ✅ | decode 経路 (`xpress: invalid length escape`) |
| 7 | match offset > 出力済みバイト数は拒否 | [MS-XCA] §2.4 | ✅ | `offset_bounds` |
| 8 | match コピーは 1 バイトずつ (重複コピー許容) | [MS-XCA] §2.4 | ✅ | `roundtrip_various` (`[7u8; 100_000]`) |
| 9 | match flag に入力が残らない場合は正常終端 (エンコーダの 1-bit パディング) | [MS-XCA] §2.4 | ✅ | `spec_example_match` (末尾 `0xffff` パディング) |
| 10 | flag word 読了後に入力が残らない場合も正常終端 | [MS-XCA] §2.4 + Windows 実装挙動 | ✅ | `trailing_flag_word_without_data` (旧 Windows エンコーダ出力) |
| 11 | `decode_with_size` は出力バッファサイズで終端 (仕様の DecompressBuffer セマンティクス) | [MS-XCA] §2.4 | ✅ | `trailing_flag_word_without_data` |
| 12 | 切り詰め flag word / match word / 拡張長の拒否 | [MS-XCA] §2.4 | ✅ | `rejects_truncated` |
| 13 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode` |

## LZ77+Huffman (Xpress Huffman)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 14 | ブロック先頭に 256 バイトの符号長テーブル (512 シンボル × 4bit nibble) | [MS-XCA] §2.1.4.1 | ✅ | `xpress_huffman_spec_example_*` (統合) |
| 15 | canonical Huffman コード、最大符号長 15bit、Kraft 和検証 (incomplete / over-subscribed 拒否)。エンコーダ側も修復後に complete code を保証 | [MS-XCA] §2.1.4.1 | ✅ | `code_lengths_kraft`、`rejects_bad_table`、`test_xpress_huff_oversubscribed` |
| 16 | シンボル <256 はリテラル、256 は EOF、>256 はマッチ | [MS-XCA] §2.1.4.3 | ✅ | `xpress_huffman_spec_example_*` (統合) |
| 17 | EOF 判定: シンボル 256 かつ入力全消費かつ (既知の場合) 出力完備。それ以外の 256 は len 3/dist 1 マッチとして処理 | [MS-XCA] §2.1.4.3 | ✅ | `multi_block`、`roundtrip_various` (反復データで 256 マッチを通過) |
| 18 | ブロックは非圧縮 64 KiB 単位、マルチブロック対応 | [MS-XCA] §2.1.4.2 | ✅ | `multi_block` |
| 19 | ビットストリームは MSB-first、デコーダは 32bit 先読み + Pos1/Pos2/Pos の 3 ポインタ連動 | [MS-XCA] §2.1.4.3 | ✅ | `xpress_huffman_spec_example_*` (統合) |
| 20 | マッチ長: ベース値 + (15 の場合) 拡張バイト + (0xff の場合) 16bit 拡張。拡張バイトはバイトカーソルで読む | [MS-XCA] §2.1.4.3 | ✅ | `xpress_huffman_spec_example_match` (統合、len=297 経路) |
| 21 | オフセット bit 幅はシンボル値から算出 (上位ビット + 可変下位ビット) | [MS-XCA] §2.1.4.3 | ✅ | `xpress_huffman_spec_example_match` (統合) |
| 22 | match コピーは 1 バイトずつ (重複コピー許容) | [MS-XCA] §2.1.4.3 | ✅ | `xpress_huffman_spec_example_match` (統合) |
| 23 | match offset > 出力済みバイト数は拒否 | [MS-XCA] §2.1.4.3 | ✅ | decode 経路 (`xpress-huff: match offset before start`) |
| 24 | 切り詰めテーブル / ビットストリームの拒否 | [MS-XCA] §2.1.4.3 | ✅ | `rejects_truncated` |
| 25 | `decode_bounded` / `decode_with_size` で出力を制御 | crate contract | ✅ | `bounded_decode` |

## LZNT1

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 26 | 16-bit LE チャンクヘッダ: bit15=圧縮フラグ、bit14:12=signature 0x3、bit11:0=サイズ-3 | [MS-XCA] §2.5 | ✅ | `lznt1_stored_chunk`、`lznt1_compressed_chunk_*` (統合) |
| 27 | signature != 3 の拒否 | [MS-XCA] §2.5 | ✅ | `rejects_bad_signature` |
| 28 | 非圧縮チャンクは raw コピー | [MS-XCA] §2.5 | ✅ | `lznt1_stored_chunk` (統合) |
| 29 | 圧縮チャンク: flag byte + 最大 8 要素 (LSB 順) | [MS-XCA] §2.5 | ✅ | `lznt1_compressed_chunk_literals` (統合) |
| 30 | compressed word: 出力位置 U に応じ displacement 4..12bit (上位) + length-3 (下位 16-M bit) | [MS-XCA] §2.5 | ✅ | `displacement_bit_schedule`、`lznt1_compressed_chunk_match` (統合) |
| 31 | displacement > 出力済みバイト数は拒否 | [MS-XCA] §2.5 | ✅ | decode 経路 (`lznt1: displacement before start`) |
| 32 | match コピーは 1 バイトずつ (重複コピー許容) | [MS-XCA] §2.5 | ✅ | `lznt1_compressed_chunk_match` (統合) |
| 33 | header=0 は End_of_buffer。マーカー省略のバッファも末尾で正常終端 | [MS-XCA] §2.5 | ✅ | `end_of_buffer_marker`、decode 経路 |
| 34 | 切り詰めヘッダ / チャンクの拒否 | [MS-XCA] §2.5 | ✅ | `rejects_truncated_chunk` |
| 35 | チャンクは非圧縮 4096 バイト単位 | [MS-XCA] §2.5 | ✅ | `roundtrip_various` (5000B/40000B 入力) |
| 36 | `decode_bounded` で出力上限を強制 | crate contract | ✅ | `bounded_decode` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 37 | 3 バリアント全てで decode→encode→decode ラウンドトリップ | [MS-XCA](https://learn.microsoft.com/openspecs/windows_protocols/ms-xca/) | ✅ | `roundtrip_various`、`xca_roundtrips` (統合) |
| 38 | LZNT1 エンコーダは縮小しない場合に非圧縮チャンクを選択 | [MS-XCA] §2.5 | ✅ | `uncompressed_chunk_roundtrip` |
| 39 | LZNT1 エンコーダは常に End_of_buffer マーカーを付与 | [MS-XCA] §2.5 | ✅ | `end_of_buffer_marker` |
| 40 | エンコーダのマッチ探索は greedy 単一候補ハッシュ (3B プレフィックス)。Windows との出力バイト一致は保証しない (仕様上の正当なバリエーション) | 実装選択 | ✅ | roundtrip で検証。known-answer は decode 側のみ |

## 出典 / 検証メモ

- known-answer ベクタは [MS-XCA] §3 ("Examples") および Samba `lib/compression` テストスイート (GPLv3+) 内の Windows `RtlCompressBuffer` エンコーダ出力を使用。テストデータとしてバイト列のみ参照し、コードの移植は行っていない。
- MS-XCA ストリームに自己記述メタデータは存在しないため、`decode_with_size` は仕様が前提とする出力バッファサイズ駆動の終端を提供する。
