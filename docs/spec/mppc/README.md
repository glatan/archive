# MPPC (RFC 2118)

| 項目 | 内容 |
|------|------|
| 形式概要 | RFC 2118 "Microsoft Point-To-Point Compression Protocol (MPPC)"。LZ77 系のパケット指向圧縮。8192 バイトの履歴バッファを跨パケットで維持し、各パケットは 4bit フラグニブル + 12bit coherency count + データで構成される |
| 基準仕様 | [RFC 2118](https://www.rfc-editor.org/rfc/rfc2118) (ローカルスナップショット: `docs/spec/sources/rfc2118.txt`) |
| 実装 | `archive::compress::mppc` (Encoder / Decoder / encode / decode / decode_bounded)。pure-Rust 実装 |

## 対応バリアント・スコープ

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| RFC 2118 パケット (flags + count + token stream) | RFC 2118 §3-4 | ✅ | ✅ | 単一パケット API と stateful な Encoder/Decoder の双方を提供 |
| PPP カプセル化 (protocol `0x00FD`, CCP ネゴシエーション) | RFC 2118 §2, §3, §4.3 | ❌ | ❌ | intentional scope。パケット本体の codec のみで、リンク層の protocol field・CCP・Reset-Request/Ack 処理は対象外 |
| RDP bulk compression 64KiB "big" 辞書バリアント | MS-RDPEGDI 系仕様 | ❌ | ❌ | intentional scope。RFC 2118 の 8192B 履歴のみ対象 |
| MPPE 暗号 | RFC 3078/3079 | ❌ | ❌ | 別プロトコル |

## パケットヘッダ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | パケット先頭はフラグニブル (A/B/C/D) + 12bit coherency count の 2 バイト。パケット自体に長さフィールドはなく、バイト列 = 1 パケットとして処理する | RFC 2118 §3.1 | ✅ | `literal_roundtrip` 他 |
| 2 | Bit A (FLUSHED, `0x8`): 履歴をゼロ初期化し書き込み位置を先頭に戻す。受信側は count をリセットして受け入れる | RFC 2118 §3.1 Bit A | ✅ | `reset`、`front_wrap`、fixture `wrap_front.pkts` |
| 3 | Bit B (FRONT, `0x4`): 履歴の書き込み位置をバッファ先頭に戻す (送信側が末尾に空きがなかった場合の巻き戻し通知) | RFC 2118 §3.1 Bit B | ✅ | `front_wrap`、fixture `wrap_front.pkts` |
| 4 | Bit C (COMPRESSED, `0x2`): データが LZ トークン列。未設定なら非圧縮データ (後述の flush 規則により履歴は更新しない) | RFC 2118 §3.1 Bit C | ✅ | `expansion_fallback` |
| 5 | Bit D (`0x1`): 予約ビット。立っていれば拒否 | RFC 2118 §3.1 Bit D | ✅ | `rejects_reserved_flag` |
| 6 | coherency count は 12bit、パケット毎に +1 (mod 4096)。前パケットの期待値と異なると拒否。最初のパケットは FLUSHED 有無に関わらずその count を基準として採用する (crate 側の寛容方針) | RFC 2118 §3, §3.1 | ✅ | `coherency_count_checked` |

## トークン列 (ビットストリーム)

MSB-first でパックされる (RFC 2118 §4.2)。

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 7 | リテラル `< 0x80`: 先頭 bit `0` + 下位 7bit (即ちバイトそのもの) | RFC 2118 §4.1 Literal Encoding | ✅ | `known_answer_literal_and_copy` |
| 8 | リテラル `>= 0x80`: `10` + 下位 7bit | RFC 2118 §4.1 | ✅ | `high_literal_roundtrip`、fixture `high_literals` |
| 9 | Copy offset `<64`: `1111` + 6bit | RFC 2118 §4.2.1 Offset Encoding | ✅ | `known_answer_literal_and_copy` |
| 10 | Copy offset `64..=319`: `1110` + 8bit (値 - 64) | RFC 2118 §4.2.1 | ✅ | `known_answer_mid_offsets` |
| 11 | Copy offset `320..=8191`: `110` + 13bit (値 - 320) | RFC 2118 §4.2.1 | ✅ | `known_answer_mid_offsets`、fixture `offsets` 相当 |
| 12 | match length `3`: bit `0`。それ以外: 先頭 `k` 個の `1` + `0` + `k+1` bit の下位値 (`2^(k+1) + value`)。k ≤ 11 で最大 8191。`k > 11` は拒否 | RFC 2118 §4.2.2 Length-of-Match Encoding | ✅ | 全 roundtrip + `rejects_truncated_bitstream` |
| 13 | Copy 参照位置は `(書き込み位置 - offset) mod 8192` のリング参照。offset 分だけ遡った履歴バイトを 1 バイトずつ複写 (オーバーラップ可) | RFC 2118 §4 (導入部) + 参照実装 (rdesktop/FreeRDP) の挙動 | ✅ | `overlap` fixture、oracle 検証 |
| 14 | トークン列終端はバッファ末尾。最終バイトの残り bit はゼロパディングとして受理。全ゼロ末尾バイトはパディングではなくリテラル `0x00` としてデコードする | RFC 2118 §4 + crate 判定 | ✅ | roundtrip 系 |
| 15 | 1 パケットの出力が履歴バッファ残量を超える場合は拒否 (適合送信側は必ず FRONT で折り返す) | RFC 2118 §3.1 Bit B | ✅ | `rejects_history_overflow` |

## 履歴 / 状態管理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 16 | 履歴バッファ 8192 バイト、初期値ゼロ。FLUSHED でゼロ初期化 + 位置リセット | RFC 2118 §1, §3, §3.1 Bit A | ✅ | `reset` |
| 17 | 非圧縮パケットは履歴を更新しない。RFC 2118 §3 "Data Expansion" は expansion 送信後に sender が履歴を flush して次パケットで FLUSHED を立てることを要求しており、参照実装 (rdesktop, FreeRDP) も非圧縮パケットの履歴更新を行わない | RFC 2118 §3 + 参照実装挙動 | ✅ | `expansion_fallback` |
| 18 | エンコーダは expansion (圧縮結果 >= 入力) の場合 C=0 の非圧縮パケットを出し、次パケットに FLUSHED を立てる | RFC 2118 §3 "Data Expansion" | ✅ | `expansion_fallback` |
| 19 | エンコーダは `pos + len > 8192` の場合 FRONT を立てて書き込み位置を 0 に戻す | RFC 2118 §3.1 Bit B | ✅ | `front_wrap` |
| 20 | 1 パケットのペイロードは最大 8192 バイト (履歴サイズ)。超過入力は InvalidData。マルチパケット化は呼び出し側のパケット化責任 | RFC 2118 §1, §3 | ✅ | `payload_too_large`、`oversized_input_rejected` (統合) |

## API / 単一ショット

| # | 要件 | 状態 | テスト名 / 備考 |
|---|------|------|----------------|
| 21 | `encode(input)` は 1 パケット (FLUSHED, count=0) を返す。input は ≤ 8192B | ✅ | `literal_roundtrip` 他 |
| 22 | `decode(input)` / `decode_bounded` は入力全体を 1 パケットとして新規 Decoder でデコード | ✅ | fixture decode テスト |
| 23 | `Encoder::compress` / `Decoder::decompress` はパケット単位の stateful API。実 PPP ストリームのパケット境界はリンク層由来のため呼び出し側が供給する | ✅ | `multi_packet_history`、統合 `decode_multi_packet_streams` |
| 24 | `decode_bounded` / `decompress(max_output)` は `OutputLimitExceeded` で出力量を制限 | ✅ | `output_limit` |

## バリデーション / エラー処理

| # | 要件 | 状態 | テスト名 / 備考 |
|---|------|------|----------------|
| 25 | ヘッダ 2 バイト未満の入力は拒否 | ✅ | `rejects_truncated_header` |
| 26 | 予約 Bit D は拒否 | ✅ | `rejects_reserved_flag` |
| 27 | トークン列の途中切れ (offset/length の読み込み不足) は拒否 | ✅ | `rejects_truncated_bitstream` |
| 28 | match length クラス `k > 11` は拒否 | ✅ | `rejects_bad_length_class` |
| 29 | coherency count 不一致は拒否 | ✅ | `coherency_count_checked` |

## 相互運用 / テスト資産

| # | 内容 | 状態 |
|---|------|------|
| 30 | エンコード方向 interop: 本 crate エンコーダの出力パケット列を rdesktop の MPPC デコーダ (GPL-3.0、テスト時オラクルのみ) でデコードし、10 ケース全件一致を確認 (リテラル・コピー各 offset クラス・重複コピー・FLUSHED/FRONT・expansion fallback・8192B フルパケット・マルチパケット) | ✅ (`.local/mppc_oracle/`。git 管理外のローカル検証であり、clone 後の再現は rdesktop 取得が前提) |
| 31 | fixture: `tests/fixtures/mppc/` に単一パケット `*.pkt` + `*.expected` 6 組と `[u16 LE len][packet]` 連接 `*.pkts` + `*.expected` 2 組。全件本 crate エンコーダ生成 + rdesktop オラクル検証済み | ✅ |
| 32 | デコード方向 interop: 外部 MPPC エンコーダ生成ベクタ | ⚠️ 未確保 (rdesktop/FreeRDP に利用可能な standalone encoder がなく、KAT + 双方向自己検証で代替) |

## Intentional scope / 既知制約

- PPP カプセル化 (protocol `0x00FD`、CCP、Reset-Request/Ack) はリンク層の責任として対象外。
- RDP MPPC の 64KiB 辞書モード・FLUSH semantics の RDP 固有差異は対象外 (RFC 2118 の 8KiB 履歴のみ)。
- エンコーダは greedy 単一ハッシュのベースライン品質 (圧縮率最適化は意図しない)。
- RFC 2118 §1.1 の licensing statement (MPPC は PPP 実装製品かつ相互運用目的でのみ使用可、というフィールドオブユース制限) を記録する。本 crate は PPP 非実装の汎用ライブラリとして codec を単体公開しており、透明性のため THIRD_PARTY_NOTICES にも明記 (法的助言ではない)。
- `decode(input)` は入力全体を 1 パケットとして扱う。パケット長フィールドが wire 上に存在しないため、連接ストリームの split は仕様上不可能 (パケット境界はリンク層情報)。
- fuzz ハーネスは MPPC の 1 パケット上限に合わせて入力を 8192 バイトに丸める (`fuzz/src/runner.rs` の `Algorithm::Mppc` 特例)。
