# pea

| 項目 | 内容 |
|------|------|
| 形式概要 | PeaZip の PEA (Pack, Encrypt, Authenticate) 1.x アーカイブ。10B アーカイブヘッダ + POD ストリームヘッダ + オブジェクト列 + EOA トリガ + ストリーム/ボリューム完全性タグ |
| 基準仕様 | 「PEA file format specifications and implementation notes」(`pea_help.pdf`) および参照実装 `pea.pas` / `pea_utils.pas` (PeaZip, LGPLv3) — `docs/spec/sources/` にスナップショット |
| 参照実装 | PeaZip `pea.pas` / `pea_utils.pas` (LGPLv3、ワイヤ形式の動作参照 — spec-informed、コード取り込みなし)、独自 Python PEA writer/parser (統合テストの oracle)。詳細: THIRD_PARTY_NOTICES pea 項 |
| 実装 | `archive::archive::pea::{decode, encode}` (単一ストリーム read/write)。`pea` feature 配下 (`zlib` feature に依存) |

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
| 18 | 認証付き暗号ストリーム (EAX/TF/SP/HMAC + カスケード、コード 48-51, 65-76) | ❌ intentional scope | crypto subheader + パスワード鍵導出が必要。archive 展開の領域外。各プリミティブの一次仕様は公開済み (manifest `no_url_available` `pea-crypto-specs`) が crypto 実装前提のため scope 維持 |
| 19 | マルチボリューム分割結合 | ❌ intentional scope | 単一ファイル内ではボリュームタグのみ処理。`.pea` 分割出力の結合は split/join 側機能 |
| 20 | EOS 後のマルチストリーム生成・暗号ストリーム出力 | ⚠️ | 単一ストリームの PEA 書き込みは `PeaEncoder` で実装済み (stored / PCOMPRESS2 deflate、CRC32/ADLER32/CRC64/MD5/SHA1/SHA256 タグの出力に対応)。`pea_encode_roundtrip`, `pea_encode_compressed_roundtrip`, `pea_encode_control_algo_selection`, `test_pea_encode_python_oracle`, `test_pea_archive_encoder_trait`。EOS 後のストリーム追加および暗号化ストリーム出力は intentional scope 外とする |
| 21 | 属性・タイムスタンプのファイルシステム適用 | ❌ intentional scope | SETATTR/RESETATTR は OS 依存。raw 値として公開 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 17 |
| ⚠️ 部分対応  | 1 |
| ❌ 未対応  | 3 (intentional scope) |
| **合計** | **21** |
