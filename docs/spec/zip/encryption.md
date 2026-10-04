# ZIP — encryption (Traditional / Strong / AES)

## §6 Traditional PKWARE Encryption

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 102 | 鍵初期化: Key(0)=305419896, Key(1)=591751049, Key(2)=878082192 | §6 | ✅ | `TraditionalZipCrypto::new()` |
| 103 | CRC-32 ベース update 関数 | §6 | ✅ | `TraditionalZipCrypto::update()` |
| 104 | 12B 暗号化ヘッダー | §6 | ✅ | `encode_traditional_payload()` |
| 105 | 復号後ヘッダー末尾 = CRC high byte or mod_time high byte | §6 | ✅ | `traditional_verifier()` |
| 106 | wrong password 検出 | §6 | ✅ | `test_roundtrip_traditional_wrong_password_rejected` |

---

## §7 Strong Encryption Specification

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 107 | DES / 3DES / RC2 / RC4 encryption | §7.2.3 | ❌ | intentional non-support: APPNOTE §10.1 が実装に PKWARE との別途ライセンス契約を要求。bit 6 検出時は `Unsupported` を返す (`test_strong_encryption_rejected_other_algorithms`) |
| 108 | AES 128/192/256 via Strong Encryption Header | §7.2.3 | ❌ | intentional non-support (§10.1 同上)。extra field 0x0017 は検出用にパースのみ (`test_strong_encryption_rejected_aes`) |
| 109 | Certificate-based encryption | §7.2.4 | ❌ | 未対応 (intentional) |
| 110 | Central Directory Encryption | §7.5 | ❌ | intentional non-support (§10.1 同上)。Archive Decryption Header (§4.3.10) は検出して `Unsupported` を返す (`test_central_directory_encryption_rejected`) |

---

## Appendix E — WinZip AE-x Encryption (Method 99)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 116 | Compression method = 99, actual method in 0x9901 extra | Appendix E | ✅ | `test_roundtrip_aes_encrypted_single_file` |
| 117 | AE-1 (vendor version 1): CRC-32 を格納 | Appendix E.6.1 | ✅ | 対応 |
| 118 | AE-2 (vendor version 2): CRC-32 = 0 | Appendix E.6.2 | ✅ | CRC 検証スキップ |
| 119 | PBKDF2-HMAC-SHA1 鍵導出 (1000 iterations) | WinZip AES spec | ✅ | `pbkdf2_hmac_sha1()` |
| 120 | Salt 長: AES-128=8B, AES-192=12B, AES-256=16B | WinZip AES spec | ✅ | `ZipAesStrength::salt_len()` |
| 121 | Password verifier (2B) | WinZip AES spec | ✅ | `test_roundtrip_aes_wrong_password_rejected` |
| 122 | HMAC-SHA1 authentication code (先頭 10B) | WinZip AES spec | ✅ | `test_zip_aes_roundtrip_and_password_failure` |
| 123 | AES-CTR (ZIP-compatible mode) | WinZip AES spec | ✅ | `apply_zip_aes_ctr()` |
| 124 | AE-3+ (vendor version 3+) reject | WinZip AES spec | ✅ | `Unsupported("zip: AES vendor version > 2 (AE-3+)")` |

---
