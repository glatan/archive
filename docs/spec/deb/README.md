# deb (Debian binary package)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [deb(5)](https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html) — dpkg パッケージフォーマット (Debian マニュアルページ、ローカルスナップショット: `docs/spec/sources/deb_5_unstable.html`) |
| 参照実装 | GNU `ar` / GNU `tar` / `bsdtar` (interop oracle)。詳細: THIRD_PARTY_NOTICES deb 項 |
| 形式概要 | `ar` アーカイブ + 固定 member レイアウト: `debian-binary` / `control.tar.*` / `data.tar.*` |
| 実装範囲 | read/write 両対応 (固定 member レイアウトの組み立て + member 圧縮) |

`deb(5)` 参照: <https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| ar コンテナ (GNU 拡張名対応) | [deb(5)](https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html) | ✅ | ✅ | `DebEncoder` / `encode`。deb(5) は "no long file name extensions" + trailing-slash 15 文字制約を規定するが、decode は ar 層の拡張名解決をそのまま受理する (lenient) |
| member 圧縮: 無圧縮 / `.gz` / `.xz` / `.zst` / `.bz2` / `.lzma` / `.Z` | [deb(5) permitted compressions](https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html) | ✅ | ✅ | control.tar は none/gz/xz/zst のみ (deb(5))、bz2/lzma は data.tar のみ。`.Z` は両者とも deb(5) 非掲載の legacy 拡張 (decode 受理・encode 可だが control には拒否) |
| thin ar (`!<thin>`) メンバー | [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html) | ✅ | — | thin member はファイルシステム参照として扱わない。encoder は通常 ar のみ発行 |

### コンテナレイアウト

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | `.deb` は `ar` アーカイブ (`!<arch>\n` magic) として読める | deb(5): "the file is an ar archive" | ✅ | `decode()` は `ar::decode` に委譲、`test_deb_decode_minimal` |
| 2 | GNU thin archive (`!<thin>\n`) は package として reject | deb(5): member payload must be present | ✅ | `rejects_thin_archive` |
| 3 | 先頭 member が `debian-binary` であること | deb(5): "The first member is named debian-binary" | ✅ | `rejects_debian_binary_not_first` |
| 4 | `debian-binary` member 不在 → reject | deb(5): required member | ✅ | `rejects_missing_debian_binary` |
| 5 | `debian-binary` の先頭行がフォーマットバージョン (例 `2.0`) | deb(5): "a series of lines... currently this should be 2.0" | ✅ | `parses_version_line`, `DebPackage::version` |
| 6 | バージョン行の形式検証 (`<num>.<num>`、不正は reject) + major==2 以外は停止 (deb(5): "If the major number has changed ... the program should stop") | deb(5): format version syntax / debian-binary | ✅ | `parses_version_line` (`2`, `x.y`, 空を reject), `rejects_major_version_change` (3.x reject) |
| 7 | `control.tar*` member が必須 | deb(5): "The second required member is named control.tar" | ✅ | `rejects_missing_control_and_data` |
| 8 | `data.tar*` member が必須 | deb(5): "The third required member is data.tar" | ✅ | `rejects_missing_control_and_data` |
| 9 | `control.tar*` / `data.tar*` member の重複を reject | deb(5): single required member | ✅ | `rejects_duplicate_data_member`, `rejects_duplicate_control_member` |
| 10 | member 名は厳密一致 (`control.tar` or `control.tar.<ext>`、`control.tarball` 等は非該当) | deb(5): member naming | ✅ | `rejects_name_prefix_lookalikes` |
| 11 | `debian-binary` / `control.tar*` / `data.tar*` 以外の member (署名 member 等) は `Other` として保持 | deb(5): "Programs may assume... additional members" | ✅ | `keeps_extra_members` |
| 11a | member 順序 `debian-binary` → `control.tar*` → `data.tar*` (deb(5) canonical layout) | deb(5): "The second ... control.tar" / "The third ... data.tar" | ✅ | decode 側は出現順を検証する (`rejects_data_before_control`, `rejects_member_between_required`)。`_` で始まるメンバーは deb(5) の規定に従い介在を許容する (`keeps_ignorable_member_between_required`)。encode 側 (#17) は正規の順序で出力する |
| 11b | deb(5) の ar 層制約: "no long file name extensions"、trailing slash で 15 文字、サイズ 10 桁 | deb(5): "Only the common ar archive format is supported, with no long file name extensions" | ✅ lenient | decode は ar 層の拡張名・長名を受理 (deb(5) より寛容)。encoder は通常 ar の短名のみ emit |

### tar member の圧縮

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 12 | member 圧縮 suffix の認識: 無圧縮 / `.gz` / `.xz` / `.zst` / `.bz2` / `.lzma` / `.Z`。deb(5) の許容集合は member ごとに異なる (control.tar: none/gz/xz/zst、data.tar: それ + bz2/lzma) が、decode は両 member で全 suffix を受理する (lenient) | deb(5): permitted compressions + legacy compress | ✅ | `member_compression`, `test_deb_decode_compressed_members` |
| 13 | 未認識 suffix → `Unsupported` | deb(5): permitted compressions | ✅ | `rejects_unknown_member_compression` |
| 14 | `data.tar*` の伸張結果を tar entry として公開 | deb(5): data member = tar of payload | ✅ | `data_entries()`, `test_deb_decode_minimal` |
| 15 | `control.tar*` の伸張結果を tar entry として公開 | deb(5): control member = tar of metadata | ✅ | `control_entries()`, `test_deb_decode_minimal` |
| 16 | 伸張の output limit (bounded decode) を各 codec に伝搬 | crate bounded-decode convention | ✅ | `bounded_decode_enforces_limit` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | member 順序 `debian-binary` → `control.tar<ext>` → `data.tar<ext>` → extra members を emit | deb(5) member layout | ✅ | `roundtrip_uncompressed`, `test_deb_encoder_roundtrip` |
| 18 | `debian-binary` は `<version>\n` (既定 `2.0`)。`version()` は `2.<num>` のみ受理 (major=2 固定) | deb(5) format version | ✅ | `version_validation` |
| 19 | control/data は file リストから内部で `TarEncoder` 生成、または ready-made tar bytes (`set_control_tar`/`set_data_tar`) | deb(5): tar members | ✅ | `roundtrip_uncompressed`, `raw_tar_and_extra_members` |
| 20 | member 圧縮は `DebCompression` 全 7 種 (`.gz`/`.xz`/`.zst`/`.bz2`/`.lzma`/`.Z`/無圧縮) を emit、control/data は別指定可、member 名に suffix 付与。control.tar は deb(5) 準拠で none/gz/xz/zst のみ (bz2/lzma/.Z は `finish()` で reject) | deb(5) permitted compressions | ✅ | `roundtrip_compressed_members`, `separate_compressions`, `control_tar_compression_restricted` |
| 21 | extra member (署名等) は必須 member の後に call 順で emit | deb(5): "additional members may follow" | ✅ | `raw_tar_and_extra_members` |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 22 | system `ar` + `tar` + `gzip` で組み立てた `.deb` を decode | system interop | ✅ | `test_deb_decode_system_built_package` |
| 23 | crate で組み立てた `.deb` から `bsdtar` が member を byte 一致で抽出、GNU `ar t` が member 順を列挙 | system interop | ✅ | `test_deb_crate_built_extracted_by_bsdtar`, `test_deb_encoder_bsdtar_interop` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 24 | `!<arch>\ndebian-binary` 先頭で `.deb` を自動検出 (plain `ar` より優先) | CLI detection | ✅ | `detect_deb`, `detect_plain_ar_not_deb` |
| 25 | `archive extract` は `data.tar` の内容を展開 (生 member は `--format ar` で取得) | CLI semantics | ✅ | `extract.rs` の `Format::Deb` アーム |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 26 | `control` ファイルの deb822 セマンティクス | deb-control(5) | ❌ | コンテナレイヤの責務外 (intentional)。`control_entries()` で生ファイルは取得可能。`debian-binary` 2 行目以降は deb(5) 準拠で ignore (#5/#6) |
| 27 | `data.tar` 内の filesystem セマンティクス (conffiles, maintainer scripts) | [deb(5)](https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html) | ❌ | パッケージマネージャ層の責務 (intentional) |

### 実装メモ

- `ar` レイヤは thin archive (`!<thin>\n`) も受理するが、`deb` レイヤは `debian-binary` 先頭 member を要求するため thin archive は deb としては reject される。
