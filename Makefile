# netdump Makefile — Build release binaries for musl targets and package tarballs.
#
# Targets:
#   release          Build both targets and produce tarballs (default)
#   build-x86_64     Build x86_64-unknown-linux-musl only
#   build-aarch64    Build aarch64-unknown-linux-musl only
#   clean            Remove cargo artifacts
#   distclean        Remove all generated files (target + dist)

# 优先从 git tag 提取版本（如 v0.1.0 → 0.1.0），无 tag 时回退到 Cargo.toml
GIT_VERSION := $(shell git describe --tags --dirty 2>/dev/null | sed 's/^v//')
VERSION     := $(or $(GIT_VERSION),$(shell sed -n '/^version/{s/.*"\(.*\)"/\1/p;q}' Cargo.toml))

DIST       := dist
BINARY     := netdump
TARGET_DIR := target

ARCH_X86_64  := x86_64-unknown-linux-musl
ARCH_AARCH64 := aarch64-unknown-linux-musl

ARCHIVES := \
	$(DIST)/$(BINARY)-$(VERSION)-$(ARCH_X86_64).tar.gz \
	$(DIST)/$(BINARY)-$(VERSION)-$(ARCH_AARCH64).tar.gz

.PHONY: release build-x86_64 build-aarch64 clean distclean

# ── default ──────────────────────────────────────────────────────────────────

release: $(ARCHIVES)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  All builds completed. Artifacts in $(DIST)/"
	@echo "═══════════════════════════════════════════════════════════"

# ── per-target build ─────────────────────────────────────────────────────────

build-x86_64:
	@rustup target list --installed 2>/dev/null | grep -q "^$(ARCH_X86_64)$$" \
		|| rustup target add $(ARCH_X86_64)
	cargo build --release --target $(ARCH_X86_64)

build-aarch64:
	@rustup target list --installed 2>/dev/null | grep -q "^$(ARCH_AARCH64)$$" \
		|| rustup target add $(ARCH_AARCH64)
	cargo build --release --target $(ARCH_AARCH64)

# ── packaging ────────────────────────────────────────────────────────────────

$(DIST):
	mkdir -p $(DIST)

$(DIST)/$(BINARY)-$(VERSION)-$(ARCH_X86_64).tar.gz: build-x86_64 | $(DIST)
	@echo "==> Packaging $(BINARY)-$(VERSION)-$(ARCH_X86_64).tar.gz ..."
	tmp=$$(mktemp -d) && \
	cp $(TARGET_DIR)/$(ARCH_X86_64)/release/$(BINARY) $$tmp/ && \
	cp LICENSE $$tmp/ && \
	tar czf "$@" -C $$tmp . && \
	rm -rf $$tmp
	@echo "    Done: $@"

$(DIST)/$(BINARY)-$(VERSION)-$(ARCH_AARCH64).tar.gz: build-aarch64 | $(DIST)
	@echo "==> Packaging $(BINARY)-$(VERSION)-$(ARCH_AARCH64).tar.gz ..."
	tmp=$$(mktemp -d) && \
	cp $(TARGET_DIR)/$(ARCH_AARCH64)/release/$(BINARY) $$tmp/ && \
	cp LICENSE $$tmp/ && \
	tar czf "$@" -C $$tmp . && \
	rm -rf $$tmp
	@echo "    Done: $@"

# ── clean ────────────────────────────────────────────────────────────────────

clean:
	cargo clean

distclean: clean
	rm -rf $(DIST)
