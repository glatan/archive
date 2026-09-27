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

TTY 出力時は自動的に `$PAGER` (デフォルト `less -FRX`) を通します。
1 画面に収まる場合は即表示、長い場合はスクロール可能です。
`--no-pager` またはパイプ先がある場合は pager を使いません。

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

`.deb` は `data.tar` の内容を展開します。生の member (`debian-binary` / `control.tar.*`) は `--format ar` で展開してください。

### `archive pack <format> <input...> -o <output>`

新しい archive を作成。

```sh
archive pack tar src/ docs/ -o backup.tar
archive pack zip src/ -o release.zip --password secret
archive pack 7z data/ -o archive.7z
archive pack cpio files/ -o archive.cpio --overwrite
```

対応フォーマット: `tar`, `cpio`, `ar`, `zpaq`, `zip`, `7z`, `lha`, `arj`, `arc`

### `archive compress <format> <input> -o <output>`

単体圧縮ファイルを作成。

```sh
archive compress gzip data.bin -o data.bin.gz
archive compress zstd data.bin -o data.bin.zst
archive compress bzip2 data.bin -o data.bin.bz2 --level 9
archive compress lrzip data.bin -o data.bin.lrz --backend bzip2
```

対応フォーマット: `gzip`, `zstd`, `zstd-seekable`, `bzip2`, `lzip`, `lzma`, `lzw`, `lz4`, `lzo`, `lrzip`, `rzip`, `zlib`, `snappy`, `brotli`, `deflate`, `xz`, `zpaq`, `xpress`, `xpress-huff`, `lznt1`, `lzf`, `fastlz`, `lzsa`, `lzsa2`, `lzrw1`, `lzrw1a`, `lzrw2`, `lzrw3`, `lzrw3a`, `zx0`, `zx1`, `zx2`, `zx5`, `vcdiff`, `mppc`, `lzs`, `lzxd`, `cmpsc`

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

magic bytes からフォーマットを自動検出します。
`.deb` は `!<arch>\n` の直後の member 名 `debian-binary` で識別され、汎用 `ar` より優先されます。
`.rpm` は Lead magic `ED AB EE DB` で識別されます (read のみ、署名検証は対象外)。
`.squashfs` は `hsqs` magic で識別されます (read のみ、LZMA1 image は非対応)。
`.cab` は `MSCF` magic で識別されます (read のみ、MSZIP/stored のみ対応、Quantum/LZX/マルチキャビネットは非対応)。
`.zim` は magic `0x044D495A` で識別されます (read のみ、entry 名は namespace prefix 付き)。
`.mtree` は `#mtree` signature で識別されます (manifest 形式のため `read` でメタデータ一覧、`extract` は非対応)。
`.warc` は `WARC/1.0` / `WARC/1.1` version line で識別されます (read のみ。`.warc.gz` は gzip として伸張してから読み込みます)。
`.lzh` は offset 2 の `-l`-`-` メソッドマーカー + offset 20 の header level byte で識別されます (store メソッドのみ。`-lh5-` 等の圧縮エントリは非対応)。
`.arj` は `0x60 0xEA` signature で識別されます (method 0 stored のみ。圧縮・暗号化エントリは非対応)。
`.arc` は `0x1A` marker + method byte で識別されます (method 1/2 stored のみ。packed/squeezed/crunched は非対応)。
lzsa ストリームは `7b 9e` magic + traits byte で識別されます (raw ブロックは検出不可のため `--format` が必要)。
検出できない場合 (raw deflate, brotli, snappy, lzma, xpress, xpress-huff, lznt1, lzf, fastlz, lzrw1, lzrw1a, lzrw2, lzrw3, lzrw3a, zx0, zx1, zx2, zx5, mppc, lzs, lzxd, cmpsc など) は `--format` で明示してください。
lzxd の decode はストリーム外パラメータのウィンドウサイズに最大値 (32MiB) を仮定します (小さいウィンドウで作られたストリームも正しく decode できます)。
cmpsc は PKWARE APPNOTE method-16 コンテナ (辞書ヘッダ + 展開辞書 + CMPSC データ) を扱います。encode は alphabet-only 辞書を使うためデータは実質非圧縮です。

## ライセンス

AGPL-3.0-only
