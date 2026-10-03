# crx3

| 項目 | 内容 |
|------|------|
| 形式概要 | Chrome 拡張パッケージ。`Cr24` magic + version 3 + protobuf `CrxFileHeader` + ZIP アーカイブ |
| 基準仕様 | Chromium `components/crx_file/crx3.proto` (`docs/spec/sources/crx3.proto` にスナップショット) |
| 参照実装 | 独自 Python protobuf/zip ジェネレータ (interop oracle)。詳細: THIRD_PARTY_NOTICES crx3 項 |
| 実装 | `archive::archive::crx3::decode` (read のみ)。`crx3` feature 配下 (`zip` feature に依存) |

## コンテナ層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | magic `Cr24` (offset 0, 4B) 検証 | crx3.proto ファイルフォーマットコメント | ✅ | `rejects_bad_inputs` |
| 2 | version == 3 (LE u32) のみ受理 | 同上 | ✅ | `rejects_bad_inputs` |
| 3 | header 長 N (LE u32) で `CrxFileHeader` を区切る | 同上 | ✅ | 全テスト |
| 4 | N が過大なものを拒否 (16 MiB 上限) | crx3.proto 「reject CRX₃ files that contain an N that is too large」 | ✅ | `rejects_bad_inputs` |
| 5 | ヘッダ末尾以降を ZIP アーカイブとして decode | 同上 | ✅ | `test_crx3_python_oracle` |
| 6 | ヘッダ後が ZIP でない入力を拒否 | 同上 | ✅ | `test_crx3_rejects_non_zip_tail` |

## protobuf ヘッダ層 (CrxFileHeader)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 7 | `sha256_with_rsa` (field 2, repeated) → proof 一覧 | crx3.proto CrxFileHeader | ✅ | `decodes_header_and_zip` |
| 8 | `sha256_with_ecdsa` (field 3, repeated) → proof 一覧 | 同上 | ✅ | `decodes_header_and_zip` |
| 9 | `verified_contents` (field 4) → gzip 圧縮 JSON を生バイトで保持 | 同上 | ✅ | `decodes_header_and_zip` |
| 10 | `signed_header_data` (field 10000) → `SignedData.crx_id` (16B) を抽出 | 同上 + SignedData message | ✅ | `decodes_header_and_zip` / oracle テスト |
| 11 | `AsymmetricKeyProof` の `public_key` (1) / `signature` (2) を保持 | crx3.proto AsymmetricKeyProof | ✅ | 全テスト |
| 12 | wire type 0 (varint) / 1 (64-bit) / 5 (32-bit) の既知フィールドは値をスキップして継続、wire type 3/4/6/7 (SGROUP/EGROUP/reserved) ・不正 varint・範囲外フィールド番号・LEN 長超過を拒否 | protobuf wire format | ✅ | `for_each_len_field` (decode.rs:107-143)、`rejects_bad_inputs` |
| 13 | 未知フィールドはスキップ (proto2 の前方互換) | proto2 仕様 | ✅ | for_each_len_field の既定分岐 |
| 15 | crx_id と公開鍵の整合性検証 | crx3.proto SignedData (crx_id = SHA-256(public_key) 先頭 16B) | ✅ | `Crx3Image::verify_crx_id` で `sha256_with_rsa` の先頭公開鍵と照合する。`crx_id_matches_rsa_pubkey`, `crx_id_mismatch_reported`, `crx_id_none_when_no_signed_data` |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 14 | 署名検証 (RSA-PSS / ECDSA P-256) | ❌ intentional scope | proof の中身は公開するが検証はしない。検証には RSA/ECDSA 実装が必要で archive 展開の領域外 |
| 16 | verified_contents の中身検証 | ❌ intentional scope | gzip JSON の展開・照合は拡張署名検証の一部 |
| 17 | CRX2 / CRX write | ❌ intentional scope | version 3 のみ。作成は Chromium 側ツールの領域 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 14 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 3 (intentional scope) |
| **合計** | **17** |
