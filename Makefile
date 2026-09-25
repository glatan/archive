DEBUG_IMAGE = archive-debug
TEST_IMAGE = archive-test
FUZZ_IMAGE = archive-fuzz

FUZZ_ALGORITHM ?= all
FUZZ_DURATION ?= 60
FUZZ_PATTERN ?= all

.PHONY: test
test:
	podman run --rm $(TEST_IMAGE)

.PHONY: fuzz
fuzz:
	podman run --rm \
		-v ./fuzz/failures:/workspace/fuzz/failures \
		-v ./fuzz/corpus:/workspace/fuzz/corpus \
		$(FUZZ_IMAGE) \
		--algorithm $(FUZZ_ALGORITHM) \
		--duration $(FUZZ_DURATION) \
		--pattern $(FUZZ_PATTERN)

.PHONY: debug-shell
debug-shell:
	podman run --rm -it $(DEBUG_IMAGE)

.PHONY: fetch-spec-sources
fetch-spec-sources:
	python3 docs/spec/sources/fetch.py

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
