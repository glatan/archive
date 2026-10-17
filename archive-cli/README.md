# archive-cli

`archive` ライブラリの全フォーマットをコマンドラインから操作する binary package。

## インストール

```sh
cargo install --path archive-cli
```

## コマンド一覧

### `archive inspect <input>`

検出フォーマット、entry 数、scope note を表示。

```sh
archive inspect sample.tar.gz
archive inspect sample.7z --json
archive inspect encrypted.zip --password secret
```

### `archive list <input>`

entry 一覧を表示。

```sh
archive list sample.tar.gz                    # 一行一 entry
archive list sample.tar.gz --long             # サイズ・mode・mtime 付き
archive list sample.tar.gz --tree             # ツリー表示
archive list sample.tar.gz --json             # JSON 出力
archive list sample.tar.gz --no-pager         # pager を無効化
```

TTY 出力時は自動的に `$PAGER` (デフォルト `less -FRX`) を経由して出力する。
1 画面に収まる場合は即座に表示し、長い場合はスクロールできる。
`--no-pager` の指定時やパイプへの出力時は pager を使用しない。

### `archive test <input>`

decode と checksum 検証を実行し、整合性を確認。

```sh
archive test sample.tar.gz
archive test encrypted.7z --password secret --json
```

### `archive extract <input>`

archive を展開、または単体圧縮ファイルを復元。

```sh
archive extract sample.tar.gz                          # カレントディレクトリに展開
archive extract sample.tar.gz --out /tmp/dest           # 出力先を指定
archive extract sample.zip --password secret            # 暗号化 zip
archive extract sample.tar.gz dir/file.txt              # 特定 entry のみ
archive extract sample.tar.gz --overwrite               # 既存ファイルを上書き
archive extract sample.deb                              # data.tar ペイロードを展開
archive extract sample.rpm                              # cpio payload の内容を展開
archive extract image.sqfs                              # squashfs 内の regular file を展開
```

`.deb` は `data.tar` の内容を展開する。生の member (`debian-binary` / `control.tar.*`) は `--format ar` で展開する。出力先に既にあるシンボリックリンクは、ディレクトリの途中でも最終成分でも拒否する。`--overwrite` は通常ファイルだけを切り詰める。

### `archive pack <format> <input...> -o <output>`

新しい archive を作成。

```sh
archive pack tar src/ docs/ -o backup.tar
archive pack zip src/ -o release.zip --password secret
archive pack 7z data/ -o archive.7z
archive pack cpio files/ -o archive.cpio --overwrite
```

対応フォーマット: `tar`, `cpio`, `ar`, `zpaq`, `zip`, `7z`, `lha`, `arj`, `arc`, `git-pack` (ファイルを blob オブジェクトとして格納。non-deltified), `xar` (sha1 チェックサム + gzip エンコード)

### `archive compress <format> <input> -o <output>`

単体圧縮ファイルを作成。

```sh
archive compress gzip data.bin -o data.bin.gz
archive compress zstd data.bin -o data.bin.zst
archive compress bzip2 data.bin -o data.bin.bz2 --level 9
archive compress lrzip data.bin -o data.bin.lrz --backend bzip2
```

対応フォーマット: `gzip`, `zstd`, `zstd-seekable`, `bzip2`, `lzip`, `lzma`, `lzw`, `lz4`, `lzo`, `lrzip`, `rzip`, `zlib`, `snappy`, `brotli`, `deflate`, `xz`, `zpaq`, `xpress`, `xpress-huff`, `lznt1`, `lzf`, `fastlz`, `lzsa`, `lzsa2`, `lzrw1`, `lzrw1a`, `lzrw2`, `lzrw3`, `lzrw3a`, `zx0`, `zx1`, `zx2`, `zx5`, `zx0b`, `zx1b`, `zx2b`, `zx5b`, `vcdiff`, `mppc`, `lzs`, `lzxd`, `cmpsc`

`--level` は gzip (0-9), bzip2 (1-9), rzip (1-9), lzw (9-16), zpaq (1-3) で有効。
`--backend` は lrzip のみ (`none`, `bzip2`, `lzo`, `lzma`, `gzip`, `zpaq`)。

## 共通オプション

| オプション | 対応コマンド | 説明 |
|-----------|------------|------|
| `--format <fmt>` | inspect, list, test, extract | フォーマット自動検出を上書き |
| `--password <pw>` | inspect, list, test, extract, pack | 暗号化 zip/7z のパスワード |
| `--json` | inspect, list, test | JSON 形式で出力 |
| `--overwrite` | extract, pack | 既存ファイルを上書き |

## フォーマット自動検出

magic bytes からフォーマットを自動検出する。

- `.deb`: `!<arch>\n` 直後の member 名 `debian-binary` で識別（汎用 `ar` より優先）。
- `.rpm`: Lead magic `ED AB EE DB` で識別（read のみ、署名検証は対象外）。
- `.squashfs`: `hsqs` magic で識別（read のみ、LZMA1 image は非対応）。
- `.cab`: `MSCF` magic で識別（read のみ、MSZIP/stored のみ対応、Quantum/LZX/マルチキャビネットは非対応）。
- `.zim`: magic `0x044D495A` で識別（read のみ、entry 名は namespace prefix 付き）。
- `.mtree`: `#mtree` signature で識別（manifest 形式のため `read` でメタデータ一覧取得、`extract` は非対応）。
- `.warc`: `WARC/1.0` / `WARC/1.1` version line で識別（read のみ。`.warc.gz` は gzip として伸張後に読み込み）。
- `.pack`: `PACK` + version 2 ヘッダで識別（v3 は未検出）。エントリ名は hex オブジェクト ID。
- `.xar`: `xar!` magic で識別（stored/gzip エンコード対応、拡張属性・署名は対象外）。
- `.lzh`: offset 2 の `-l`-`-` メソッドマーカー + offset 20 の header level byte で識別（store メソッドのみ。`-lh5-` 等の圧縮エントリは非対応）。
- `.arj`: `0x60 0xEA` signature で識別（method 0 stored のみ。圧縮・暗号化エントリは非対応）。
- `.arc`: `0x1A` marker + method byte で識別（method 1/2 stored のみ。packed/squeezed/crunched は非対応）。
- lzsa ストリーム: `7b 9e` magic + traits byte で識別（raw ブロックは検出不可であり、CLI ではストリームのみ対応 — raw ブロックは library API のみ）。

自動検出に対応しない形式（raw deflate, brotli, snappy, lzma, xpress, xpress-huff, lznt1, lzf, fastlz, lzrw1, lzrw1a, lzrw2, lzrw3, lzrw3a, zx0, zx1, zx2, zx5, zx0b, zx1b, zx2b, zx5b, mppc, lzs, lzxd, cmpsc など）は `--format` で明示する。
lzxd の decode は、ストリーム外パラメータであるウィンドウサイズに仕様上の最大値（32MiB）を仮定してデコードする。小さいウィンドウで生成されたストリームであっても、後方参照距離はそのウィンドウサイズ以下に収まるため正常に展開できる。
cmpsc は PKWARE APPNOTE method-16 コンテナ（辞書ヘッダ + 展開辞書 + CMPSC データ）を扱う。encode は alphabet-only 辞書を使うためデータは実質非圧縮となる。

## ライセンス

AGPL-3.0-only
