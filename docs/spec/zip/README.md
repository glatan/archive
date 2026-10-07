# ZIP (APPNOTE.TXT 6.3.10)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [APPNOTE.TXT 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) (PKWARE, 2024、ローカルスナップショット: `docs/spec/sources/APPNOTE_6.3.10.txt`) |
| 参照実装 | hwzip 2.4 (public domain、method 1-6 の移植元・fixture 生成)、Info-ZIP `unshrink.c`/`unreduce.c`/`explode.c` (decode 動作参照)、blast.c (zlib license、method 10 decode の移植元)、CPython `zipfile` (PSF、SFX 検出 heuristic の動作参照)、system `zip`/`unzip`/`unar` (テスト時 oracle)。詳細: THIRD_PARTY_NOTICES zip 項 |
| current scope | split/spanned (multi-disk) を含む読み取り、compression method 0 (Store) / 1 (Shrunk) / 2-5 (Reduced) / 6 (Implode) / 8 (Deflate) / 9 (Deflate64) / 10 (DCL Implode, decode) / 12 (BZIP2) / 14 (LZMA) / 93 (Zstd) / 95 (XZ) / 98 (PPMd) / 16 (IBM z/OS CMPSC、`cmpsc` feature で decode のみ)、Traditional PKZIP encryption、WinZip AES-128/192/256、extra field 0x000a/0x000d/0x5455/0x6375/0x7075、Archive Extra Data Record / Digital Signature / ZIP64 extensible data sector スキップ |
| intentional exclusion | Certificate-based encryption (§7.2.4)、Method 7 (Tokenizing、仕様未公開)、IBM z/OS CMPSC Entropy Encoding 拡張 (Method 16 の拡張要素、特許状況未確認 — basic method の decode は対応済み)、JPEG (Method 96、WinZip 独自の JPEG 再圧縮で非公式文書のみ)、WavPack (Method 97、可逆圧縮コアの bit-level 仕様なし) |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| method 0 (Store) / 8 (Deflate) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §4.4.5, §5.8 | ✅ | ✅ | |
| method 1 (Shrunk) / 2-5 (Reduced) / 6 (Implode) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.1-§5.6 + Info-ZIP `unshrink.c`/`unreduce.c`/`explode.c` + hwzip 解説 (manifest `no_url_available` `hwzip-legacy-zip`) | ✅ | ✅ | decode + encode (hwzip 参照実装を移植) |
| method 9 (Deflate64) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.6 + Info-ZIP/hwzip de facto | ✅ | ✅ | decode + encode |
| method 12 (BZIP2) / 14 (LZMA) / 93 (Zstd) / 95 (XZ) / 98 (PPMd) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.7-§5.10 | ✅ | ✅ | 各 feature で encode 対応 |
| method 10 (DCL Implode) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) + blast.c 参照実装 | ✅ | ❌ | decode のみ |
| method 16 (CMPSC) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.17 | ✅ | ❌ | basic method の decode (`cmpsc` feature で `compress::cmpsc::decode` へ配線、無効時は `Unsupported`)。entropy-encoding 拡張は対象外 |
| method 96 (JPEG) / 97 (WavPack) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ❌ | ❌ | intentional exclusion |
| ZIP64 (§4.3.14-15 EOCD+locator, §4.5.3 extra field) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ✅ | ✅ | auto-promotion 対応 |
| Traditional PKZIP encryption (§6) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ✅ | ✅ | |
| WinZip AES-128/192/256 (Method 99, extra field 0x9901) | [WinZip AE-x spec](https://www.winzip.com/en/support/aes-encryption/) | ✅ | ✅ | |
| Strong Encryption (§7) / Central Directory Encryption (§7.5) | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ❌ | ❌ | intentional non-support: §10.1 により実装に PKWARE との別途ライセンス契約が義務付けられているため。bit 6 / extra 0x0017 / ADH は検出して `Unsupported` を返す |
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
| ✅ 実装+テスト済み | 150 |
| ⚠️ 部分実装 | 2 |
| ❌ 未実装 | 6 |
| — 該当なし | 1 |
| **合計** | **159** |

**カバー率**: 150 / 159 = **94.3%** (仕様全体)、150 / 152 = **98.7%** (intentional exclusion および該当なし除外後)
