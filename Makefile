DEBUG_IMAGE = archive-debug
TEST_IMAGE = archive-test
FUZZ_IMAGE = archive-fuzz

FUZZ_ALGORITHM ?= all
FUZZ_DURATION ?= 60
FUZZ_PATTERN ?= all
FUZZ_JOBS ?= 1
# corrupt な zpaq は 2^32 要素のモデルを確保しようとする。overcommit 下では
# try_reserve が成功し、OOM killer がプロセスを殺す。ulimit -v の単位は KiB。
# 既定 2GiB のソフト上限で確保をデコーダのエラーとして返す。
# -S だけを変える。ハード上限を下げると外部ツールが 4GiB へ戻せない。
FUZZ_AS_KB ?= 2097152
# zpaq-level3 の encode は 2GiB を超える。qemu-user のオーバーヘッドも
# あるため、aarch64 だけ 4GiB を既定にする。FUZZ_JOBS > 1 は 4GiB でも
# 不足しうる。
FUZZ_AS_KB_AARCH64 ?= 4194304

# イメージ内で x86_64（SSE2）の全テスト、aarch64（NEON）の lib テスト、
# x86-64-v3（AVX2）の lib テストを順に実行する。
.PHONY: test
test:
	podman run --rm $(TEST_IMAGE)

# x86_64（SSE2）、AVX2、AVX-512、i686（SSE2）、aarch64（NEON）、
# wasm32（simd128）は失敗とコーパスを分けて書く。
# `make -j6 fuzz` で 6 本を同時に起動する。`-j` を付けないときは順に実行する。
.PHONY: fuzz
fuzz: fuzz-x86_64 fuzz-avx2 fuzz-avx512 fuzz-i686 fuzz-aarch64 fuzz-wasm

.PHONY: fuzz-x86_64
fuzz-x86_64:
	mkdir -p fuzz/failures/x86_64 fuzz/corpus/x86_64
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/x86_64:/workspace/fuzz/failures \
		-v ./fuzz/corpus/x86_64:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v $(FUZZ_AS_KB) && exec /usr/local/bin/archive-fuzz-x86_64 run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

.PHONY: clean-fuzz
clean-fuzz:
	cargo run -q --profile fuzz -p archive-fuzz -- clean

# x86-64-v3 向けにコンパイルした公開経路。AVX2 を実行時には選ばない。
# テストイメージで実行する。ホスト CPU に AVX2 が無いときは SIGILL で失敗する。
.PHONY: test-avx2
test-avx2:
	podman run --rm --entrypoint /bin/sh $(TEST_IMAGE) \
		-c 'CARGO_TARGET_DIR=target/avx2 RUSTFLAGS="-C target-cpu=x86-64-v3" cargo test --lib --all-features'

# x86-64-v4 向けにコンパイルした公開経路。AVX-512 を実行時には選ばない。
# テストイメージで実行する。ホスト CPU に AVX-512 が無いときは SIGILL で失敗する。
# 既定の `make test` には入れない。
.PHONY: test-avx512
test-avx512:
	podman run --rm --entrypoint /bin/sh $(TEST_IMAGE) \
		-c 'CARGO_TARGET_DIR=target/avx512 RUSTFLAGS="-C target-cpu=x86-64-v4" cargo test --lib --all-features'

# i686 の既定ターゲットは SSE2 が有効。テストイメージの 32-bit ローダで実行する。
# 既定の `make test` には入れない。
.PHONY: test-i686
test-i686:
	podman run --rm --entrypoint cargo $(TEST_IMAGE) \
		test --lib --all-features --target i686-unknown-linux-gnu

# generated artifact 回帰を 32-bit で実行する。zpaq 系は import していない。
.PHONY: test-i686-generated
test-i686-generated:
	podman run --rm --entrypoint cargo $(TEST_IMAGE) \
		test --test integration --all-features --target i686-unknown-linux-gnu generated_tests::

# wasm32 の既定ターゲットに simd128 は無い。テストイメージで `+simd128` の check を実行する。
# `scripts/archive-features.py` は std を除く。既定の `make test` には入れない。
.PHONY: test-wasm
test-wasm:
	podman run --rm --entrypoint /bin/sh $(TEST_IMAGE) \
		-c 'RUSTFLAGS="-C target-feature=+simd128" cargo check --lib --no-default-features --features "$$(cat /usr/local/share/archive-features)" --target wasm32-unknown-unknown'

.PHONY: fuzz-avx2
fuzz-avx2:
	mkdir -p fuzz/failures/avx2 fuzz/corpus/avx2
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/avx2:/workspace/fuzz/failures \
		-v ./fuzz/corpus/avx2:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v $(FUZZ_AS_KB) && exec /usr/local/bin/archive-fuzz-avx2 run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

# x86-64-v4 向けにコンパイルした公開経路。AVX-512 を実行時には選ばない。
# ホスト CPU に AVX-512 が無いときは SIGILL で失敗する。
.PHONY: fuzz-avx512
fuzz-avx512:
	mkdir -p fuzz/failures/avx512 fuzz/corpus/avx512
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/avx512:/workspace/fuzz/failures \
		-v ./fuzz/corpus/avx512:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v $(FUZZ_AS_KB) && exec /usr/local/bin/archive-fuzz-avx512 run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

# i686 の既定 SSE2。イメージ内の 32-bit ローダで実行する。
.PHONY: fuzz-i686
fuzz-i686:
	mkdir -p fuzz/failures/i686 fuzz/corpus/i686
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/i686:/workspace/fuzz/failures \
		-v ./fuzz/corpus/i686:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v $(FUZZ_AS_KB) && exec /usr/local/bin/archive-fuzz-i686 run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

# wasm32 + simd128。ゲストは wasmtime 上で動き、外部ツールはホストの
# archive-fuzz-wasm がプロセスグループと ulimit 付きで起動する。
# 共有メモリは 2GiB を起動時に予約する。2GiB のソフト上限では連続領域が
# 取れないので、このプロセスだけ 4GiB にする。ゲストの線形メモリ上限は 2GiB。
.PHONY: fuzz-wasm
fuzz-wasm:
	mkdir -p fuzz/failures/wasm fuzz/corpus/wasm
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/wasm:/workspace/fuzz/failures \
		-v ./fuzz/corpus/wasm:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v 4194304 && exec /usr/local/bin/archive-fuzz-wasm run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

# aarch64 の公開経路は NEON。qemu-user で実行する。
# zpaq-level3 の encode は 2GiB を超えるため、このターゲットだけ
# ソフト上限を 4GiB にする。FUZZ_JOBS > 1 は 4GiB でも不足しうる。
.PHONY: fuzz-aarch64
fuzz-aarch64:
	@if [ "$(FUZZ_JOBS)" -gt 1 ]; then echo "warning: fuzz-aarch64 with FUZZ_JOBS=$(FUZZ_JOBS) can exhaust the 4GiB limit (see fuzz/README.md)"; fi
	mkdir -p fuzz/failures/aarch64 fuzz/corpus/aarch64
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/aarch64:/workspace/fuzz/failures \
		-v ./fuzz/corpus/aarch64:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v $(FUZZ_AS_KB_AARCH64) && exec qemu-aarch64 -L /usr/aarch64-linux-gnu /usr/local/bin/archive-fuzz-aarch64 run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

.PHONY: debug-shell
debug-shell:
	podman run --rm -it $(DEBUG_IMAGE)

.PHONY: fetch-spec-sources
fetch-spec-sources:
	python3 docs/spec/sources/fetch.py

.PHONY: check-features
check-features:
	python3 scripts/check-features.py

.PHONY: build-container
build-container: build-container.debug build-container.test build-container.fuzz

.PHONY: build-container.test
build-container.test:
	podman build --target test -t $(TEST_IMAGE) -f Containerfile .
	podman image prune -f

.PHONY: build-container.debug
build-container.debug:
	podman build --target debug -t $(DEBUG_IMAGE) -f Containerfile .
	podman image prune -f

.PHONY: build-container.fuzz
build-container.fuzz:
	podman build --target fuzz -t $(FUZZ_IMAGE) -f Containerfile .
	podman image prune -f

# ── performance comparison ──────────────────────────────────────
# `make bench` keeps the existing Criterion microbenchmarks.
# `make bench-compare` runs the reference comparison harness on the host.
# Missing reference tools are reported as N/A in the generated report.
BENCH_OUT ?= target/bench/container

.PHONY: bench
bench:
	cargo bench --all-features --bench compress --bench archive

.PHONY: bench-compare
bench-compare:
	cargo build --release -p archive-cli --bin archive --bin archive-bench-helper
	cargo bench --all-features --bench compare -- --full

.PHONY: bench-compare-quick
bench-compare-quick:
	cargo build --release -p archive-cli --bin archive --bin archive-bench-helper
	cargo bench --all-features --bench compare -- --quick

.PHONY: bench-baseline
bench-baseline:
	cargo build --release -p archive-cli --bin archive --bin archive-bench-helper
	cargo bench --all-features --bench compare -- --full --output-dir target/bench/baseline

.PHONY: bench-refs
bench-refs:
	bash docs/bench/refs/build.sh

# Referenced tools live in the test image. Build it first so the source
# snapshot matches the working tree.
.PHONY: bench-compare-container
bench-compare-container: build-container.test
	mkdir -p $(BENCH_OUT) target/bench/refs
	podman run --rm \
		-v "$(CURDIR)/$(BENCH_OUT):/workspace/bench-out:Z" \
		-v "$(CURDIR)/target/bench/refs:/workspace/target/bench/refs:Z" \
		--entrypoint /bin/sh $(TEST_IMAGE) \
		-c 'cargo build --release -p archive-cli --bin archive --bin archive-bench-helper && \
		    cargo bench --all-features --bench compare -- --full \
		      --output-dir /workspace/bench-out/run-$$(date +%s%N)'
