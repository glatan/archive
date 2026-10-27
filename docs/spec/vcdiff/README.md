# VCDIFF (RFC 3284)

| 項目 | 内容 |
|------|------|
| 形式概要 | RFC 3284 "The VCDIFF Generic Differencing and Compression Data Format"。ターゲットを一連のウィンドウとして記述するデルタ形式。各ウィンドウは ADD / RUN / COPY 命令列で構成され、COPY アドレスは source セグメントと生成済みターゲットを連結した仮想アドレス空間を指す。アドレス符号化は VCD_SELF / VCD_HERE / near キャッシュ / same キャッシュの 9 モード |
| 基準仕様 | [RFC 3284](https://www.rfc-editor.org/rfc/rfc3284) (ローカルスナップショット: `docs/spec/sources/rfc3284.txt`) |
| 参照実装 | xdelta3 3.2.0 (Apache-2.0、既知解答ベクタ生成および双方向 decode 検証の fixture/oracle。コード移植なし)。性能比較 (`docs/bench/`) では xdelta3 3.2.2 を empty source の encode/decode 参照として使用。詳細: THIRD_PARTY_NOTICES VCDIFF 項 |
| 実装 | `archive::compress::vcdiff` (decode / decode_with_source / decode_bounded / encode / encode_with_source / encode_with_windows)。pure-Rust 実装 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| RFC 3284 基本形式 (デフォルトコードテーブル) | RFC 3284 §4-6 | ✅ | ✅ | |
| `VCD_TARGET` ウィンドウ (source = 既デコード target) | RFC 3284 §4.2 | ✅ | ✅ | decode は受理 (S/T 境界またぎ COPY 拒否は VCD_SOURCE と同規約)。encode は `encode_with_windows` が直前 target 領域を source とする VCD_TARGET ウィンドウを emit |
| `VCD_CODETABLE` アプリケーション定義コードテーブル | RFC 3284 §7 | ❌ | ❌ | intentional scope (同上) |
| `VCD_DECOMPRESS` 二次圧縮セクション | RFC 3284 §4.1/§4.3 | ❌ | ❌ | intentional scope (二次圧縮器の形式は RFC 範囲外) |
| `VCD_APPHEADER` (hdr indicator `0x04`) | xdelta3 拡張 | ✅ | n/a | 受信して skip (xdelta3 出力の interop 用) |
| `VCD_ADLER32` (win indicator `0x04`) | xdelta3 拡張 | ✅ | n/a | ウィンドウ Adler-32 を検証。エンコード側は出力しない (任意要素) |

## ストリーム構造 (ヘッダ / ウィンドウ)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 3 バイトは `0xD6 0xC3 0xC4` ('V','C','D' + MSB)。4 バイト目 (Header4) は将来のバージョン予約で、値は検査せず受理する | RFC 3284 §4.1 | ✅ | `vcdiff_rejects_malformed` (統合) |
| 2 | Hdr_Indicator: `VCD_DECOMPRESS` / `VCD_CODETABLE` は Unsupported として拒否、未定義ビットは InvalidData | RFC 3284 §4.1 | ✅ | `rejects_unsupported_flags` |
| 3 | 各ウィンドウは Win_Indicator + [source segment size + position] + delta encoding | RFC 3284 §4.2 | ✅ | `vcdiff_xdelta3_source_window` (統合) |
| 4 | Win_Indicator の SOURCE/TARGET 両方同時指定は拒否、未定義ビットは拒否 | RFC 3284 §4.2 | ✅ | `rejects_source_and_target_both_set`、`rejects_reserved_header_bits`、`vcdiff_rejects_malformed` (統合) |
| 5 | `VCD_SOURCE` 指定時は source file の (position, size) 範囲を source セグメントとして使用。範囲外は拒否 | RFC 3284 §4.2 | ✅ | `vcdiff_xdelta3_*` (統合) |
| 6 | delta encoding は「長さ varint」+「target length + Delta_Indicator + 3 セクション長 + 3 セクション」。長さ不一致・セクション長不整合は拒否 | RFC 3284 §4.3 | ✅ | `rejects_section_length_mismatch`、`vcdiff_rejects_malformed` (統合) |
| 7 | Delta_Indicator 非零 (セクション別二次圧縮) は Unsupported として拒否 | RFC 3284 §4.3 | ✅ | `rejects_unsupported_flags` |
| 8 | 整数は base-128 varint (7bit/バイト、MSB 継続、上位桁先行) | RFC 3284 §2 | ✅ | 全ベクタ + roundtrip |

## 命令 / アドレスデコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 9 | 命令コードは 256 エントリのコードテーブルを索引し、1 エントリは最大 2 命令 (type, size, mode) を持つ。size=0 は別途 inst ストリームに varint で続く | RFC 3284 §6 | ✅ | `vcdiff_xdelta3_*` (統合) |
| 10 | デフォルトコードテーブル: RUN(1) + ADD(18) + COPY 9 モード×16 (単独) + ペアエントリ 163-255 | RFC 3284 §5.6 depiction | ✅ | 同上 |
| 11 | ADD: data セクションから size バイト転写、不足は拒否 | RFC 3284 §3 | ✅ | `rejects_copy_out_of_range` / malformed 系 |
| 12 | RUN: data セクションの 1 バイトを size 回繰り返し | RFC 3284 §3 | ✅ | `roundtrip_no_source` |
| 13 | COPY: アドレス `a` から size バイトを仮想空間 (source ++ 生成済み target) から前方 1 バイトずつ複写 (オーバーラップ可) | RFC 3284 §3 | ✅ | `roundtrip_self_copy` |
| 14 | VCD_SELF (mode 0): アドレスを varint 直書き | RFC 3284 §5.3 | ✅ | `vcdiff_xdelta3_*` (統合) |
| 15 | VCD_HERE (mode 1): `here - addr` の varint、here = source 長 + 生成済み長。アンダーフローは拒否 | RFC 3284 §5.3 | ✅ | `vcdiff_xdelta3_*` (統合) |
| 16 | near モード (2..s_near+1): `near[m-2] + varint`。s_near=4 | RFC 3284 §5.3 | ✅ | `vcdiff_xdelta3_near_same_caches` (統合) |
| 17 | same モード (s_near+2..s_near+s_same+1): `same[(m-(s_near+2))*256 + b]`、b は 1 バイト。s_same=3 | RFC 3284 §5.3 | ✅ | `vcdiff_xdelta3_near_same_caches` (統合) |
| 18 | キャッシュ更新: COPY 処理ごとに near[next_slot]=addr・next_slot 巡回、same[addr % (s_same*256)]=addr。ウィンドウ先頭で全スロット 0 初期化 | RFC 3284 §5.1/5.2 | ✅ | `vcdiff_xdelta3_near_same_caches` (統合) |
| 19 | ウィンドウ生成量が target length を超過/不足したら拒否 (ADD/RUN/COPY 各命令の実行前に残量を検査して早期拒否) | RFC 3284 §6 | ✅ | `rejects_target_length_mismatch`、`vcdiff_rejects_oversized_copy_size`、`vcdiff_rejects_oversized_run_size`、`vcdiff_rejects_malformed` (統合) |
| 20 | COPY アドレスが既生成範囲 (source ++ 生成済み target) を超える場合は拒否。加えて RFC §3 の表明に従い、S/T 境界を跨ぐ複写区間も拒否 | RFC 3284 §3 + crate contract | ✅ | `rejects_copy_out_of_range`、`rejects_copy_spanning_source_boundary` |
| 21 | 複数ウィンドウ連接のサポート | RFC 3284 §4 | ✅ | `multi_window` (単体。fixture は全件単一ウィンドウ) |

## xdelta3 拡張の受理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 22 | `VCD_APPHEADER` (hdr `0x04`): 長さ varint + バイト列を読み飛ばす | xdelta3 拡張 | ✅ | `appheader_skipped` + `vcdiff_xdelta3_source_window` (統合) |
| 23 | `VCD_ADLER32` (win `0x04`): 3 セクション長の直後の 4 バイト BE Adler-32 を読み、デコード済みウィンドウと照合 | xdelta3 拡張 | ✅ | `vcdiff_rejects_bad_checksum` (統合) |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 24 | varint 途中切れ・ウィンドウ途中切れの拒否 (panic なし) | crate contract | ✅ | `rejects_truncated`、`vcdiff_rejects_malformed` (統合) |
| 25 | `decode_bounded` で合計出力上限を強制 (ウィンドウ単位の残量管理) | crate contract | ✅ | `bounded_decode` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 26 | 単一ウィンドウ出力。source 非空時は `VCD_SOURCE` + (全長, 位置 0)、空時は source 無し | RFC 3284 §4.2 | ✅ | `vcdiff_roundtrips` (統合) |
| 27 | エンコーダは greedy 単一候補マッチ探索 + RUN/ADD/COPY + SELF/HERE/near/same 最良モード選択 (§5.4 addr_encode 準拠)。ペア命令は使わない単独命令のみ出力 (仕様上正当) | RFC 3284 §5.4 | ✅ | roundtrip + xdelta3 によるデコード検証 |
| 28 | Adler-32 / appheader は出力しない (任意要素) | xdelta3 拡張 | ✅ | xdelta3 decode が受理 (警告のみ) |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 29 | CLI `--format vcdiff` で decode/encode。magic `D6 C3 C4` で自動検出も可 | crate CLI contract | ✅ | archive-cli 配線 |
| 30 | fuzz ラウンドトリップ対象 (algorithm `vcdiff` 空 source、`vcdiff-source` 非空 source)。外部ツール interop ハーネスへの接続はなし (xdelta3 は source ファイル引数を要し pipe 型 spec に合わない) | crate fuzz contract | ✅ | fuzz 配線 |

## 出典 / 検証メモ

- 基準仕様は RFC 3284 のみ。参照実装 xdelta3 3.2.0 (Joshua MacDonald, Apache-2.0) は既知解答ベクタ生成と双方向デコード検証のためにローカルでビルドして用いたが、コードの移植は行っていない (spec-informed)。
- 統合テストの `*_xdelta3.vcd` は `xdelta3 -e` で生成した既知解答ベクタ (decode のみ検証): appheader + Adler-32 付き source ウィンドウ (fox)、source 無し単一ウィンドウ (fox_nosrc)、near/same キャッシュと大サイズ COPY を含む 32KiB 差分 (big)。
- `VCD_CODETABLE` (アプリ定義コードテーブル) は参照実装 xdelta3 自身も `XD3_UNIMPLEMENTED` で拒否するため、本実装も Unsupported 拒否を intentional scope とする。`VCD_DECOMPRESS` (二次圧縮) も同様に Unsupported。`VCD_TARGET` は RFC 3284 §4.2 に従い decode/encode (`encode_with_windows`) とも対応済み。
- `VCD_APPHEADER` / `VCD_ADLER32` は RFC 3284 にはない xdelta3 拡張だが、実際の xdelta3 出力に恒常的に現れるため受理する (RFC が許容しない未割当ビットではなく、de-facto 拡張として扱う)。
- ウィンドウ内 COPY は前方 1 バイト単位の複写として実装しており、RFC §3 で許容されている「複写先と重なるオーバーラップ」を正しく扱う。
- 特許メモ: RFC 3284 §14 の IPR 節に関連し、IETF Datatracker には AT&T による IPR disclosure #40 (draft-korn-vcdiff) が存在する。内容は HTTP/1.1 上のデータ転送用途に限定した RAND 的宣言で、汎用差分圧縮ライブラリとしての本実装への実務上の影響は小さいと判断するが、透明性のため記録する。
- 参照ツールの範囲メモ: fixture 生成・動作確認に用いたのは .local/xdelta3_ref 内の xdelta3 (Apache-2.0) のみ。同リポジトリに含まれる xdelta1 系ソース (GPL-2.0) は参照・移植の対象外とする。
