# ZIP (APPNOTE.TXT 6.3.10)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [APPNOTE.TXT 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) (PKWARE, 2024、ローカルスナップショット: `docs/spec/sources/APPNOTE_6.3.10.txt`) |
| current scope | 単一ディスクアーカイブ、compression method 0 (Store) / 1 (Shrunk, decode) / 2-5 (Reduced, decode) / 6 (Implode, decode) / 8 (Deflate) / 9 (Deflate64, decode) / 12 (BZIP2) / 14 (LZMA) / 93 (Zstd) / 95 (XZ) / 98 (PPMd)、Traditional PKZIP encryption、WinZip AES-128/192/256、extra field 0x000a/0x000d/0x5455/0x6375/0x7075、Archive Extra Data Record / Digital Signature / ZIP64 extensible data sector スキップ |
| intentional exclusion | Strong Encryption 復号 (§7、パース・アルゴリズム識別は対応)、Archive Decryption Header (§4.3.10)、Central Directory Encryption (§7.5)、PKWARE DCL Implode (Method 10)、Certificate-based encryption (§7.2.4)、Method 7 (Tokenizing、仕様未公開)、IBM z/OS CMPSC Entropy Encoding 拡張 (Method 16、特許状況未確認の新規要素)、JPEG (Method 96、WinZip 独自の JPEG 再圧縮で非公式文書のみ)、WavPack (Method 97、可逆圧縮コアの bit-level 仕様なし) |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| method 0 (Store) / 8 (Deflate) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §4.4.5, §5.8 | ✅ | ✅ | |
| method 1 (Shrunk) / 2-5 (Reduced) / 6 (Implode) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.1-§5.6 | ✅ | ❌ | decode のみ |
| method 9 (Deflate64) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.6 + Info-ZIP de facto | ✅ | ❌ | decode のみ |
| method 12 (BZIP2) / 14 (LZMA) / 93 (Zstd) / 95 (XZ) / 98 (PPMd) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.7-§5.10 | ✅ | ✅ | 各 feature で encode 対応 |
| method 10 (DCL Implode) / 16 (CMPSC Entropy拡張) / 96 (JPEG) / 97 (WavPack) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ❌ | ❌ | intentional exclusion |
| ZIP64 (§4.3.14-15, §4.3.20-22) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ✅ | ✅ | auto-promotion 対応 |
| Traditional PKZIP encryption (§6) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ✅ | ✅ | |
| WinZip AES-128/192/256 (Method 99, extra field 0x9901) | [WinZip AE-x spec](https://www.winzip.com/en/support/aes-encryption/) | ✅ | ✅ | |
| Strong Encryption (§7) / Central Directory Encryption (§7.5) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ⚠️ | ❌ | パース・アルゴリズム識別のみ、復号は対象外 |
| マルチディスク (§8) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ✅ | ❌ | `decode_parts` で split/spanned archive を decode |

状態マーカー: ✅ 実装+テスト済み / ⚠️ 部分実装 / ❌ 未実装

---

## 子ファイル

| ファイル | 内容 |
|---|---|
| [structure.md](structure.md) | APPNOTE §4.1-4.4 のレコード構造・フラグ・バージョン・§8 spanning・システム互換 |
| [methods.md](methods.md) | §4.4.5 method ID + §5 各圧縮方式の詳細要件 |
| [extra-fields.md](extra-fields.md) | §4.5 extra field + Appendix D (EFS) |
| [encryption.md](encryption.md) | §6 Traditional / §7 Strong / Appendix E (WinZip AES) |
| [writer.md](writer.md) | エンコーダー・streaming writer の要件 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 151 |
| ⚠️ 部分実装 | 0 |
| ❌ 未実装 | 2 |
| — 該当なし | 1 |
| **合計** | **153** |

**カバー率**: 151 / 154 = **98%** (仕様全体)、151 / 151 = **100%** (intentional exclusion および該当なし除外後)
