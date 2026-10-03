# LZX DELTA (LZXD)

| 項目 | 内容 |
|------|------|
| 形式概要 | Microsoft LZX DELTA (LZXD)。差分パッチ圧縮用の LZX バリアントで、呼び出し側が与える reference データを subject データの前方に論理前置し、マッチオフセットが reference 側へも遡及できる |
| 基準仕様 | [[MS-PATCH]](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/) LZX DELTA Compression and Decompression (Microsoft Open Specifications、2025-08-19 rev 14.1 版、[版固定 PDF](https://officeprotocoldocs-f5hpbjgea6b8gneq.b02.azurefd.net/files/MS-PATCH/%5bMS-PATCH%5d-250819.pdf)、ローカルスナップショット: `docs/spec/sources/ms-patch_14.1_250819.pdf`) |
| 実装 | `archive::compress::lzxd` (decode / decode_all / encode)。pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | ビットストリームは 16bit little-endian ワード列を MSB-first で消費する | [MS-PATCH] 2.1.1 | ✅ | 全ベクタで検証 |
| 2 | 入力は `[u16le 圧縮チャンクサイズ][チャンクデータ]` の繰り返し。各チャンクは最終チャンクを除き 32KiB 展開。チャンクプリフィクスはバイトアラインされビットストリームの外側にある。各 32KiB チャンク末尾は最大 15bit の 0 パディングで 16bit アライン | [MS-PATCH] 2.2.1 | ✅ | `lzxd_generated_multichunk_span` (統合: ブロックがチャンク境界を跨ぐ)、`BitReader::finish_frame` でパディング処理 |
| 3 | ウィンドウサイズは 2^17 (128KiB) から 2^25 (32MiB) の冪乗で、ストリーム外から供給される。範囲外・非冪乗は拒否 | [MS-PATCH] 2.1.2 | ✅ | `rejects_bad_window` |
| 4 | reference データは subject 出力の前方に論理前置され、マッチオフセットは合計窓 (=reference+出力) 内を遡及できる | [MS-PATCH] 2.1.3 | ✅ | `lzxd_reference_data_vector` (統合) |
| 5 | 反復オフセット R0/R1/R2 は初期値 (1,1,1)。明示マッチで R 更新 (R0←off、R1←旧R0、R2←旧R1)。R1/R2 参照は swap | [MS-PATCH] 2.1.4 | ✅ | `lzxd_generated_matches_and_repeats` (統合: R0/R1/R2 全参照) |
| 6 | マッチ長は 2-32768。1 マッチは 32KiB 出力境界を跨がない | [MS-PATCH] 2.1.5 | ✅ | デコーダガード (`uncompressed boundary` 拒否) |
| 7 | position slot 数はウィンドウサイズ依存 (≤512KiB: 2*log2、それ以上: w/128KiB+34)。footer slot 36+ は常に 17bit フット | [MS-PATCH] 2.1.6 | ✅ | `pos_slot_table` |
| 8 | ストリーム先頭 1bit が E8 call translation フラグ。セット時は続く 2 ワードが 32bit translation size。E8 反転はチャンクごとに適用 | [MS-PATCH] 2.2.2 | ✅ | `lzxd_generated_e8` (統合) / `e8_reverse_basic` |

## ブロック構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 9 | 各ブロックは 3bit 型 (1=verbatim、2=aligned offset、3=uncompressed) + 24bit 非圧縮サイズ。型 0/4-7 は拒否 | [MS-PATCH] 2.3.1 | ✅ | `lzxd_rejects_invalid` (統合: 型 5 拒否) |
| 10 | ブロックはチャンク境界を跨げる。ブロックヘッダはブロック開始時にのみ出現する | [MS-PATCH] 2.3 | ✅ | `lzxd_generated_multichunk_span` (統合) |
| 11 | uncompressed ブロック: 16bit アライン → R0/R1/R2 (u32le×3) → 生バイト → 奇数サイズ時 1B パディング | [MS-PATCH] 2.3.2.1 | ✅ | `lzxd_mixed_blocks_vector` (統合: 奇数サイズ + R 更新) / `spec_example_abc` ([MS-PATCH] §3 既知解答) |
| 12 | verbatim ブロック: main 木 (256 リテラル + 8×slot 要素)、length 木 (249 要素) を pretree 符号化。フッタービットはそのままビットストリームに出力 | [MS-PATCH] 2.3.2.2 | ✅ | `lzxd_verbatim_literals_vector` 他 (統合) |
| 13 | aligned offset ブロック: verbatim と同じ構造 + 先頭に aligned 木 (8 要素、各 3bit 直接符号長)。footer>3bit は上位を生ビット・下位 3bit を aligned 木で符号化 | [MS-PATCH] 2.3.2.3 | ✅ | `lzxd_generated_aligned_block` (統合) |
| 14 | Huffman 木は pretree 符号化された符号長の差分 (mod 17) で再構築。canonical コードは「長→シンボル順」割り当て。pretree コード 17/18/19 は RLE (17=`4+getbits(4)` 個の 0、18=`20+getbits(5)` 個の 0、19=`4+getbits(1)` 個の同値繰返し) | [MS-PATCH] 2.4 / 2.5 | ✅ | `huffman_decode` / `read_tree` (lzx.rs:413-441) / 全 Huffman ブロックベクタ |
| 15 | マッチ要素: header (len≤8 → len-2、len 9-256 → 7+length 木 len-9、len≥257 → 7+248+拡長)。拡長フィールドは prefix 0 (257-512: 8bit)、10 (513-1536: 10bit)、110 (1537-5632: 12bit)、111 (257-32768: 15bit) | [MS-PATCH] 2.6 / 2.7 | ✅ | `lzxd_generated_extra_lengths` (統合: 全 4 帯域) |
| 16 | マッチオフセット: formatted = offset+2、position slot で上位、footer ビットで下位。formatted ≤ 2 (position_slot ∈ {0,1,2}) は R0/R1/R2 参照 (formatted=3 は slot_base_footer(3) 経由で real offset 1) | [MS-PATCH] 2.6 | ✅ | `lzxd_generated_matches_and_repeats` 他 (統合) |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 17 | チャンクサイズ 0・チャンクデータ切り詰め・奇数バイト残りのチャンクは拒否 | [MS-PATCH] 2.2.1 | ✅ | `rejects_bad_chunk_layout` (size0・宣言超過・prefix 不足), `rejects_truncated`, `uncompressed_roundtrip_odd_last_chunk` |
| 18 | 非合法ブロック型・超過 (over-subscribed) Huffman 木は拒否。不完全木は合法 (libmspack 検証ベクタが実際に含む) で受理し、未使用コード空間への decode は実行時エラー | [MS-PATCH] 2.3-2.5 | ✅ | `lzxd_rejects_invalid` (型 5), `huffman_decode` (over-subscribed), `huffman_accepts_incomplete_tree` |
| 19 | 出力済み+reference を超えるオフセット・32KiB 境界跨ぎマッチは拒否 | [MS-PATCH] 2.1.5 | ✅ | `lzxd_rejects_invalid` (offset 超過), `lzxd_rejects_match_crossing_chunk_boundary` |
| 20 | `decode` は期待出力サイズで厳密終端、`decode_all` はブロックの 24bit サイズで自己終端 (`max_output` 上限付き)。uncompressed ブロックの 32KiB 境界跨ぎは quota 分割で chunk プリフィクス越しに継続して受理する (跨ぎ拒否は match のみ) | crate contract | ✅ | `lzxd_decode_all_matches_decode` (統合) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 21 | `encode` は uncompressed ブロックのみからなる合法ストリームを出力する (uncompressed チャンク = 生データ + R=(1,1,1) 維持)。Huffman 符号化ブロックの生成は **intentional scope** 外 | [MS-PATCH] 2.3.2.1 | ✅ | `uncompressed_roundtrip` / `lzxd_encode_decode_roundtrip` (統合) |
| 22 | エンコーダは reference データ・E8 変換を出力しない (常に E8=0)。decode 側は両方対応 (intentional scope) | crate-local | ✅ | 上記テストで検証 |

## テスト / 相互運用

- 統合テスト内のテスト側エンコーダ (verbatim/aligned/uncompressed ブロック生成器) で作成した 8 種類のストリームを **libmspack の参照 LZXD デコーダ** (`lzxd_decompress` with `is_delta=1`、LGPL 2.1) で検証済み。libmspack 側に LZXD エンコーダ実装は存在しない (`oabc.c` はスタブ) ため、相互検証は「自作ストリームを両デコーダで一致確認」形式。
- カバレッジ: リテラルのみ / 明示マッチ + R0-R2 / 拡長全帯域 / reference データ参照 / aligned オフセット / verbatim+uncompressed 混在 / チャンク跨ぎブロック / E8 反転。
- [MS-PATCH] §3 の `"abc"` uncompressed ブロック既知解答例をユニットテストで検証 (`spec_example_abc`)。
- 実装メモ (仕様書未記載の挙動):
  - E8 反転は `chunk_base < 0x4000_0000` の場合のみ適用 (MS-PATCH/LZX 系の慣行ガード)。
  - E8 反転はブロック中間の `block_produced` ではなく各 32KiB チャンク完了時に `chunk_done` で行う。
  - `decode` は読み込み済み入力が尽きた時点でも終了可能 (入力残量を厳密には要求しない)。
  - エンコーダの bit-packing は最初のチャンクと後続チャンクでスケジュールが異なる場合がある。

## ライセンス / 出自

- 実装は [MS-PATCH] 仕様書に基づく pure-Rust 新規実装。参照コードの複製なし。
- 相互運用検証に libmspack (LGPL 2.1) を **テスト時の参照デコーダ** としてのみ使用 (成果物への組み込みなし)。
