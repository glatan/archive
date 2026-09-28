FROM archlinux:base-devel-20260315.0.500537 AS base

# パッケージマネージャーで入る外部ツール
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
      rustup \
      python brotli gzip zip unzip 7zip libarchive \
      zstd bzip2 lzip xz ncompress lz4 lzop lrzip cpio squashfs-tools git && \
    rustup default stable && \
    pacman -Scc --noconfirm

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
RUN --mount=type=cache,id=cargo-registry,target=/root/.cargo/registry \
    --mount=type=cache,id=cargo-git,target=/root/.cargo/git \
    --mount=type=cache,id=test-target,target=/workspace/target \
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
    cargo build --release -p archive-fuzz && \
    cp target/release/archive-fuzz /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/archive-fuzz"]
