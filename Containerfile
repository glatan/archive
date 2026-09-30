FROM archlinux:base-devel-20260315.0.500537 AS base

# パッケージマネージャーで入る外部ツール
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
      rustup \
      python brotli gzip zip unzip 7zip libarchive \
      zstd bzip2 lzip xz ncompress lz4 lzop lrzip cpio squashfs-tools git \
      unarchiver lhasa cabextract && \
    rustup default stable && \
    pacman -Scc --noconfirm

# arc / nomarch — Arch official に無いため Debian pool のバイナリ deb を展開
# (interop oracle 専用。どちらも libc のみに依存する静的配置なので Arch 上で動作する)
RUN mkdir /tmp/debs && cd /tmp/debs && \
    curl -fsSL -o arc.deb https://deb.debian.org/debian/pool/main/a/arc/arc_5.21q-12_amd64.deb && \
    curl -fsSL -o nomarch.deb https://deb.debian.org/debian/pool/main/n/nomarch/nomarch_1.4-4_amd64.deb && \
    echo "9dcc3eb11abad79785c2bdbac97745ce7b47229b627e6bfa10ce307d5903fdfa  arc.deb" | sha256sum -c - && \
    echo "802d37330a29481680ad74546f734e7bf542fa620eb5dd3fb8f677e722a77e1d  nomarch.deb" | sha256sum -c - && \
    mkdir arc nomarch && \
    bsdtar -C arc -xf arc.deb && bsdtar -C arc -xf arc/data.tar.xz && \
    bsdtar -C nomarch -xf nomarch.deb && bsdtar -C nomarch -xf nomarch/data.tar.xz && \
    install -m755 arc/usr/bin/arc arc/usr/bin/marc nomarch/usr/bin/nomarch /usr/bin/ && \
    install -Dm644 arc/usr/share/doc/arc/Arcinfo.gz /usr/share/doc/arc/Arcinfo.gz && \
    cd / && rm -rf /tmp/debs

# makepkg 用の非 root ユーザー
RUN useradd -m builder && \
    echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# rzip — PKGBUILD からビルド
COPY pkg/rzip/PKGBUILD /tmp/rzip/PKGBUILD
RUN chown -R builder: /tmp/rzip && \
    su builder -c "cd /tmp/rzip && makepkg -s --noconfirm" && \
    pacman -U --noconfirm /tmp/rzip/*.pkg.tar.zst && \
    rm -rf /tmp/rzip && \
    pacman -Scc --noconfirm

# zpaq — PKGBUILD からビルド
COPY pkg/zpaq/PKGBUILD /tmp/zpaq/PKGBUILD
RUN chown -R builder: /tmp/zpaq && \
    su builder -c "cd /tmp/zpaq && makepkg -s --noconfirm" && \
    pacman -U --noconfirm /tmp/zpaq/*.pkg.tar.zst && \
    rm -rf /tmp/zpaq && \
    pacman -Scc --noconfirm

# builder ユーザーは不要になるため削除
RUN userdel -r builder && \
    sed -i '/builder/d' /etc/sudoers

WORKDIR /workspace

# ── debug target ──────────────────────────────────────────────
FROM base AS debug
COPY . .
ENTRYPOINT ["bash"]

# ── test target ──────────────────────────────────────────────
FROM base AS test
COPY . .
# cargo clean -p forces the crate itself to rebuild: the cache mount's
# mtime-based fingerprints can otherwise reuse stale binaries when source
# files arrive with older mtimes (e.g. 9p/drvfs mounts).
RUN --mount=type=cache,id=cargo-registry,target=/root/.cargo/registry \
    --mount=type=cache,id=cargo-git,target=/root/.cargo/git \
    --mount=type=cache,id=test-target,target=/workspace/target \
    cargo clean -p archive && \
    cargo test --all-features --no-run && \
    cp -a target/debug /workspace/_target_debug
RUN mkdir -p target && mv _target_debug target/debug
ENTRYPOINT ["cargo", "test", "--all-features"]

# ── fuzz target ──────────────────────────────────────────────
FROM base AS fuzz
COPY . .
RUN --mount=type=cache,id=cargo-registry,target=/root/.cargo/registry \
    --mount=type=cache,id=cargo-git,target=/root/.cargo/git \
    --mount=type=cache,id=fuzz-target,target=/workspace/target \
    cargo clean -p archive -p archive-fuzz && \
    cargo build --release -p archive-fuzz && \
    cp target/release/archive-fuzz /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/archive-fuzz"]
