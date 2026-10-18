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

# makepkg 用の非 root ユーザー
RUN useradd -m builder && \
    echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# arc — Debian ソースパッケージを PKGBUILD からビルド (interop oracle 専用)
COPY pkg/arc/PKGBUILD /tmp/arc/PKGBUILD
RUN chown -R builder: /tmp/arc && \
    su builder -c "cd /tmp/arc && makepkg -s --noconfirm" && \
    pacman -U --noconfirm /tmp/arc/*.pkg.tar.zst && \
    rm -rf /tmp/arc && \
    pacman -Scc --noconfirm

# nomarch — PKGBUILD からビルド (interop oracle 専用)
COPY pkg/nomarch/PKGBUILD /tmp/nomarch/PKGBUILD
RUN chown -R builder: /tmp/nomarch && \
    su builder -c "cd /tmp/nomarch && makepkg -s --noconfirm" && \
    pacman -U --noconfirm /tmp/nomarch/*.pkg.tar.zst && \
    rm -rf /tmp/nomarch && \
    pacman -Scc --noconfirm

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
# x86_64 の SSE2 / AVX2 はこのイメージ上で直接実行する。
# aarch64 の NEON だけ qemu-user で lib テストを実行する。
# 他アーキテクチャ向けの分岐はスカラー実装で、x86_64 の比較対象として既に実行される。
FROM base AS test
RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    pacman -Sy --noconfirm qemu-user aarch64-linux-gnu-gcc && \
    pacman -Scc --noconfirm
COPY . .
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64 -L /usr/aarch64-linux-gnu"
# cargo clean -p forces the crate itself to rebuild: the cache mount's
# mtime-based fingerprints can otherwise reuse stale binaries when source
# files arrive with older mtimes (e.g. 9p/drvfs mounts). The package clean
# leaves build-script output in place, so drop that too.
RUN --mount=type=cache,id=cargo-registry,target=/root/.cargo/registry \
    --mount=type=cache,id=cargo-git,target=/root/.cargo/git \
    --mount=type=cache,id=test-target,target=/workspace/target \
    rustup show >/dev/null && \
    rustup target add aarch64-unknown-linux-gnu && \
    cargo clean -p archive && \
    { rm -rf target/debug/build/archive-* target/debug/.fingerprint/archive-* \
        target/aarch64-unknown-linux-gnu/debug/build/archive-* \
        target/aarch64-unknown-linux-gnu/debug/.fingerprint/archive-* || true; } && \
    cargo test --all-features --no-run && \
    cargo test --all-features --target aarch64-unknown-linux-gnu --lib --no-run && \
    cp -a target/debug /workspace/_target_debug && \
    cp -a target/aarch64-unknown-linux-gnu /workspace/_target_aarch64
RUN mkdir -p target && \
    mv _target_debug target/debug && \
    mv _target_aarch64 target/aarch64-unknown-linux-gnu && \
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'cargo test --all-features' \
        'cargo test --all-features --target aarch64-unknown-linux-gnu --lib' \
        > /usr/local/bin/archive-test && \
    chmod +x /usr/local/bin/archive-test
ENTRYPOINT ["/usr/local/bin/archive-test"]

# ── fuzz target ──────────────────────────────────────────────
FROM base AS fuzz
COPY . .
RUN --mount=type=cache,id=cargo-registry,target=/root/.cargo/registry \
    --mount=type=cache,id=cargo-git,target=/root/.cargo/git \
    --mount=type=cache,id=fuzz-target,target=/workspace/target \
    cargo clean -p archive -p archive-fuzz && \
    cargo build --profile fuzz -p archive-fuzz && \
    cp target/fuzz/archive-fuzz /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/archive-fuzz"]
