# pea

| 項目 | 内容 |
|------|------|
| 形式概要 | PeaZip の PEA (Pack, Encrypt, Authenticate) 1.x アーカイブ。10B アーカイブヘッダ + POD ストリームヘッダ + オブジェクト列 + EOA トリガ + ストリーム/ボリューム完全性タグ |
| 基準仕様 | 「PEA file format specifications and implementation notes」(`pea_help.pdf`) および参照実装 `pea.pas` / `pea_utils.pas` (PeaZip, LGPLv3) — `docs/spec/sources/` にスナップショット |
| 参照実装 | PeaZip `pea.pas` / `pea_utils.pas` (LGPLv3、ワイヤ形式の動作参照 — spec-informed、コード取り込みなし)、PeaZip/Ehrhardt crypto units `fcrypta.pas` / `fcaes256.pas` / `aes_eax.pas` / `aes_omac.pas` / `aes_ctr.pas` / `aes_type.pas` / `kdf.pas` / `whirl512.pas` (zlib-style permissive、暗号ストリームの KDF/暗号/認証動作参照 — 同)、独自 Python PEA writer/parser (統合テストの oracle)。詳細: THIRD_PARTY_NOTICES pea 項 |
| 実装 | `archive::archive::pea::{decode, decode_with_password, decode_with_password_bytes, decode_parts, decode_parts_with_password_bytes, encode}` (単一ストリーム read/write + AES 暗号ストリーム decode)。`pea` feature 配下 (`zlib` feature に依存) |

## ヘッダ層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | アーカイブヘッダ 10B: `$EA` magic、version/revision、ボリューム制御アルゴリズム他 | pea_help.pdf Archive header 節、`pea_archive_hdr` | ✅ | `rejects_bad_magic_version_trigger` |
| 2 | version > 1 または rev > 6 を拒否 (それ以下は後方互換で受理) | `pea_parse_archive_header` の rev 判定 | ✅ | `rejects_bad_magic_version_trigger` |
| 3 | ストリームヘッダ: `00 00 'POD' 00` + compression/ECC/stream/obj 制御バイト | `pea_stream_hdr` / `pea_parse_stream_header` | ✅ | 全テスト |
| 4 | 全整数フィールドは little-endian (word/dword/qword) | `word2bytebuf`/`dword2bytebuf`/`qword2bytebuf` | ✅ | 全テスト |
| 5 | 制御アルゴリズムコード → タグサイズ対応表 (0-3, 16-25) | `pea_parse_stream_header` の case 表 | ✅ | 全テスト |

## オブジェクト層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 6 | word name_size; 0 = トリガオブジェクト | pea.pas オブジェクト書き込み部、`trigger_eoa`/`trigger_eos` | ✅ | 全テスト |
| 7 | トリガ: `POD` (次ストリーム開始), `EOS`, `EOA` (アーカイブ終端) | 同上 | ✅ | POD/EOS/EOA 分岐 (POD 連続ストリームに対応) |
| 8 | オブジェクトヘッダ: name + filedate (4B DOS) + attributes (4B) | pea.pas 2114-2127 行 | ✅ | 全テスト |
| 9 | dir (`faDirectory` 0x10) はサイズ・データなし | pea.pas 2129 行 | ✅ | `decodes_stored_archive` |
| 10 | ファイルは qword サイズ + データ領域; 空ファイルはデータ領域なし | pea.pas 2147-2163 行 | ✅ | `decodes_stored_archive` (empty.bin) |
| 11 | PCOMPRESS0: データは生の file_size バイト | `nocompress_file` | ✅ | `decodes_stored_archive` |
| 12 | PCOMPRESS1-3: `[u32 compsize][zlib ブロック]` の繰り返し (ブロック出力 = min(残り, 1 MiB))、末尾 u32 = 最終ブロック非圧縮サイズ; compsize == 出力サイズで raw ブロック | `compress_file` / unpea 読み取り部、`zcompres.compress2` (zlib 形式) | ✅ | `decodes_compressed_archive` + Python oracle |
| 13 | オブジェクト完全性タグ: ヘッダ+非圧縮データへのハッシュを照合 | `update_obj_control_algo`/`check_obj` | ✅ | `rejects_tampered_tag` |
| 19 | マルチボリューム分割結合 | pea_help.pdf / pea.pas ボリュームタグ | ✅ | `decode_parts(&[&[u8]])` / `decode_parts_with_password_bytes` が `.pea` ボリューム断片列を結合 (各ボリュームタグの検証・除去 → payload 連結 → 通常 decode)。`decodes_multi_volume`, `rejects_bad_volume_tag`, `rejects_empty_volume_list`。分割出力側の生成は対象外 |
| 18a | 認証付き暗号ストリーム decode — AES 系 (コード 48: AES-128 CTR+HMAC-SHA1-128 / 49: AES-128 EAX / 65: AES-256 EAX) | pea_help.pdf crypto コード表 | ✅ | 16B crypto subheader (salt + password verifier) を読み、`decode_with_password*` API で PBKDF2-SHA1 (48/49) / PBKDF2-Whirlpool (65) による鍵導出 → verifier 照合 → 復号 → ストリーム認証タグ照合。`decodes_aes_hmac_stream`, `decodes_aes_eax_stream`, `decodes_aes256_eax_stream`, `rejects_wrong_password`, `rejects_bad_auth_tag`, `rejects_unsupported_encrypted_stream` |
| 20a | 単一ストリームの PEA write (stored / PCOMPRESS2 deflate + 完全性タグ出力) | pea.pas 書き込み部 | ✅ | `PeaEncoder` で stored / PCOMPRESS2 deflate、CRC32/ADLER32/CRC64/MD5/SHA1/SHA256 タグの出力に対応。`pea_encode_roundtrip`, `pea_encode_compressed_roundtrip`, `pea_encode_control_algo_selection`, `test_pea_encode_python_oracle`, `test_pea_archive_encoder_trait`。fuzz harness `pea`/`pea-store`/`pea-sha256` で roundtrip + corrupt 対象 |

## 完全性検証

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 14 | ストリームタグ: アーカイブ先頭〜EOA トリガまでのハッシュ | `update_control_algo`/`write_auth` | ✅ | 対応ハッシュで検証 (oracle) |
| 15 | ボリュームタグ: ファイル末尾のハッシュを照合、末尾ごみを拒否 | `write_volume_check` | ✅ | `test_pea_rejects_truncated` |
| 16 | 検証可能アルゴリズム: ADLER32/CRC32/CRC64/MD5/SHA1/SHA256 (crate 実装分) | decode_control_algo コード表 | ✅ | `rejects_tampered_tag` |
| 17 | RIPEMD160/SHA512/WHIRLPOOL/SHA3/BLAKE2: タグを読み飛ばす | 同上 | ✅ | crate にハッシュ実装がないため `tag_size()` 分だけ読み飛ばして未検証で受理。`skips_unverified_object_tags`, `skips_unverified_object_tags_compressed`, `rejects_truncated_object_tag` |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 18 | 認証付き暗号ストリーム decode — 非 AES 系 | ❌ intentional scope | Twofish/Serpent EAX (50, 51, 66, 67)、AES/Twofish/Serpent トリプルカスケード (68-76)、scrypt/ハイブリッド KDF 系。新規 cipher primitive と参照資料が必要 (manifest `no_url_available` `pea-crypto-specs`)。AES 系の対応は #18a |
| 20 | EOS 後のマルチストリーム生成・暗号ストリーム出力 | ❌ intentional scope | 単一ストリーム write は #20a で対応済み。EOS 後のストリーム追加および暗号化ストリーム出力は scope 外 |
| 21 | 属性・タイムスタンプのファイルシステム適用 | ❌ intentional scope | SETATTR/RESETATTR は OS 依存。raw 値として公開 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 20 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 3 (intentional scope) |
| **合計** | **23** |
