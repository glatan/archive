FROM docker.io/library/archlinux:base-devel-20261011.0.609700@sha256:061679925e5d5028f2df9395d441ce6c4b9accf0157ff3486c06b6962e014ef1 AS base

# パッケージマネージャーで入る外部ツール
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
      rustup \
      python brotli gzip zip unzip 7zip libarchive \
      zstd bzip2 lzip xz ncompress lz4 lzop lrzip cpio squashfs-tools git \
      unarchiver lhasa cabextract xdelta3 && \
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
# x86_64 の公開経路は SSE2、aarch64 は NEON。どちらも実行時検出はしない。
# i686 の既定は SSE2。lib32-glibc が 32-bit ヘッダ、lib32-gcc-libs が libgcc を渡す。
# 他アーキテクチャ向けの分岐はスカラー実装で、x86_64 の比較対象として既に実行される。
# 非テストの `std` を除く全 feature は x86_64 と aarch64 で cargo check する。
# その組み合わせの lib テストは x86_64 だけ実行する。aarch64 の lib テストは --all-features のまま。
# i686、AVX-512、wasm32 simd128 の確認はイメージ内にビルドし、
# `make test-i686`、`make test-avx512`、`make test-wasm` で実行する。既定の ENTRYPOINT には入れない。
FROM base AS test
RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    printf '\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n' >> /etc/pacman.conf && \
    pacman -Sy --noconfirm qemu-user aarch64-linux-gnu-gcc lib32-glibc lib32-gcc-libs && \
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
    rustup target add aarch64-unknown-linux-gnu i686-unknown-linux-gnu wasm32-unknown-unknown && \
    cargo clean -p archive && \
    { rm -rf target/debug/build/archive-* target/debug/.fingerprint/archive-* \
        target/aarch64-unknown-linux-gnu/debug/build/archive-* \
        target/aarch64-unknown-linux-gnu/debug/.fingerprint/archive-* \
        target/i686-unknown-linux-gnu/debug/build/archive-* \
        target/i686-unknown-linux-gnu/debug/.fingerprint/archive-* || true; } && \
    cargo test --all-features --no-run && \
    cargo test -p archive-cli --no-run && \
    cargo test -p archive-fuzz --no-run && \
    cargo test --all-features --target aarch64-unknown-linux-gnu --lib --no-run && \
    cargo test --lib --all-features --target i686-unknown-linux-gnu --no-run && \
    cargo test --test integration --all-features --target i686-unknown-linux-gnu --no-run && \
    CARGO_TARGET_DIR=target/avx2 RUSTFLAGS="-C target-cpu=x86-64-v3" \
        cargo test --lib --all-features --no-run && \
    CARGO_TARGET_DIR=target/avx512 RUSTFLAGS="-C target-cpu=x86-64-v4" \
        cargo test --lib --all-features --no-run && \
    python3 scripts/archive-features.py > /usr/local/share/archive-features && \
    cargo check --lib --no-default-features --features "$(cat /usr/local/share/archive-features)" && \
    cargo check --lib --no-default-features --features "$(cat /usr/local/share/archive-features)" --target aarch64-unknown-linux-gnu && \
    RUSTFLAGS="-C target-feature=+simd128" \
        cargo check --lib --no-default-features --features "$(cat /usr/local/share/archive-features)" --target wasm32-unknown-unknown && \
    cargo test --lib --no-default-features --features "$(cat /usr/local/share/archive-features)" --no-run && \
    cp -a target/debug /workspace/_target_debug && \
    cp -a target/aarch64-unknown-linux-gnu /workspace/_target_aarch64 && \
    cp -a target/i686-unknown-linux-gnu /workspace/_target_i686 && \
    cp -a target/avx2 /workspace/_target_avx2 && \
    cp -a target/avx512 /workspace/_target_avx512 && \
    cp -a target/wasm32-unknown-unknown /workspace/_target_wasm32
RUN mkdir -p target && \
    mv _target_debug target/debug && \
    mv _target_aarch64 target/aarch64-unknown-linux-gnu && \
    mv _target_i686 target/i686-unknown-linux-gnu && \
    mv _target_avx2 target/avx2 && \
    mv _target_avx512 target/avx512 && \
    mv _target_wasm32 target/wasm32-unknown-unknown && \
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'cargo test --all-features' \
        'cargo test -p archive-cli' \
        'cargo test -p archive-fuzz' \
        'cargo test --all-features --target aarch64-unknown-linux-gnu --lib' \
        'CARGO_TARGET_DIR=target/avx2 RUSTFLAGS="-C target-cpu=x86-64-v3" cargo test --lib --all-features' \
        'cargo test --lib --no-default-features --features "$(cat /usr/local/share/archive-features)"' \
        > /usr/local/bin/archive-test && \
    chmod +x /usr/local/bin/archive-test
ENTRYPOINT ["/usr/local/bin/archive-test"]

# ── fuzz target ──────────────────────────────────────────────
# archive-fuzz-x86_64 は SSE2。archive-fuzz-avx2 は x86-64-v3 で、
# 公開経路が AVX2 になる。archive-fuzz-avx512 は x86-64-v4 で、
# 公開経路が AVX-512BW になる。どれも実行時には選ばない。
# archive-fuzz-i686 は i686 の既定 SSE2 を、イメージ内の 32-bit ローダで実行する。
# aarch64 は NEON を qemu-user で実行する。
# archive-fuzz-wasm は wasm32 + simd128 のゲストを wasmtime で実行する。
# スレッドは wasip1-threads、外部ツールはホスト側のプロセスグループで起動する。
FROM base AS fuzz
RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    printf '\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n' >> /etc/pacman.conf && \
    pacman -Sy --noconfirm qemu-user aarch64-linux-gnu-gcc lib32-glibc lib32-gcc-libs && \
    pacman -Scc --noconfirm
COPY . .
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
RUN --mount=type=cache,id=cargo-registry,target=/root/.cargo/registry \
    --mount=type=cache,id=cargo-git,target=/root/.cargo/git \
    --mount=type=cache,id=fuzz-target,target=/workspace/target \
    rustup show >/dev/null && \
    rustup target add aarch64-unknown-linux-gnu i686-unknown-linux-gnu wasm32-wasip1-threads && \
    rustup component add rust-src && \
    cargo clean -p archive -p archive-fuzz && \
    cargo build --profile fuzz -p archive-fuzz && \
    RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --profile fuzz -p archive-fuzz --target-dir target/avx2 && \
    RUSTFLAGS="-C target-cpu=x86-64-v4" cargo build --profile fuzz -p archive-fuzz --target-dir target/avx512 && \
    cargo build --profile fuzz -p archive-fuzz --target i686-unknown-linux-gnu && \
    cargo build --profile fuzz -p archive-fuzz --target aarch64-unknown-linux-gnu && \
    RUSTC_BOOTSTRAP=1 RUSTFLAGS="-C target-feature=+simd128 -C link-arg=--max-memory=2147483648 -C panic=unwind" cargo build -Z build-std=std,panic_unwind --profile fuzz -p archive-fuzz --target wasm32-wasip1-threads && \
    cargo build --profile fuzz -p archive-fuzz --features wasm-host --bin archive-fuzz-wasm && \
    cp target/fuzz/archive-fuzz /usr/local/bin/archive-fuzz-x86_64 && \
    cp target/avx2/fuzz/archive-fuzz /usr/local/bin/archive-fuzz-avx2 && \
    cp target/avx512/fuzz/archive-fuzz /usr/local/bin/archive-fuzz-avx512 && \
    cp target/i686-unknown-linux-gnu/fuzz/archive-fuzz /usr/local/bin/archive-fuzz-i686 && \
    cp target/aarch64-unknown-linux-gnu/fuzz/archive-fuzz /usr/local/bin/archive-fuzz-aarch64 && \
    mkdir -p /usr/local/lib && \
    cp target/wasm32-wasip1-threads/fuzz/archive-fuzz.wasm /usr/local/lib/archive-fuzz.wasm && \
    cp target/fuzz/archive-fuzz-wasm /usr/local/bin/archive-fuzz-wasm
ENTRYPOINT ["/usr/local/bin/archive-fuzz-x86_64"]
