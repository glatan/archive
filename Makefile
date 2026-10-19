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

# イメージ内で x86_64（SSE2）の全テスト、aarch64（NEON）の lib テスト、
# x86-64-v3（AVX2）の lib テストを順に実行する。
.PHONY: test
test:
	podman run --rm $(TEST_IMAGE)

# x86_64（SSE2）、AVX2、aarch64（NEON）は失敗とコーパスを分けて書く。
# `make -j3 fuzz` で 3 本を同時に起動する。`-j` を付けないときは順に実行する。
.PHONY: fuzz
fuzz: fuzz-x86_64 fuzz-avx2 fuzz-aarch64

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
# ホスト CPU に AVX2 が無いときは SIGILL で失敗する。
.PHONY: test-avx2
test-avx2:
	CARGO_TARGET_DIR=target/avx2 RUSTFLAGS="-C target-cpu=x86-64-v3" \
		cargo test --lib --all-features

.PHONY: fuzz-avx2
fuzz-avx2:
	mkdir -p fuzz/failures/avx2 fuzz/corpus/avx2
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/avx2:/workspace/fuzz/failures \
		-v ./fuzz/corpus/avx2:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v $(FUZZ_AS_KB) && exec /usr/local/bin/archive-fuzz-avx2 run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

# aarch64 の公開経路は NEON。qemu-user で実行する。
.PHONY: fuzz-aarch64
fuzz-aarch64:
	mkdir -p fuzz/failures/aarch64 fuzz/corpus/aarch64
	podman run --rm --entrypoint /bin/sh \
		-v ./fuzz/failures/aarch64:/workspace/fuzz/failures \
		-v ./fuzz/corpus/aarch64:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		-c "ulimit -S -v $(FUZZ_AS_KB) && exec qemu-aarch64 -L /usr/aarch64-linux-gnu /usr/local/bin/archive-fuzz-aarch64 run --algorithm '$(FUZZ_ALGORITHM)' --duration '$(FUZZ_DURATION)' --pattern '$(FUZZ_PATTERN)' --jobs '$(FUZZ_JOBS)'"

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
