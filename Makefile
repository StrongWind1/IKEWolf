.PHONY: fmt fmt-fix lint lint-fix doc dev build check \
        test audit machete \
        hygiene check-all all \
        build-linux-x86-musl build-linux-x86-gnu \
        build-linux-arm-musl build-linux-arm-gnu \
        build-macos-arm build-macos-x86 build-macos-universal \
        build-windows-x86-msvc build-windows-x86-gnu build-windows-arm-msvc \
        dist dist-all size fix hooks clean

# Default target.
.PHONY: all
all: dist

CARGO := cargo
DIST  := dist
BIN   := ikewolf

# -- OS / architecture detection -----------------------------------------------
UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)

ifeq ($(findstring Linux,$(UNAME_S)),Linux)
  PLATFORM := linux
else ifeq ($(findstring Darwin,$(UNAME_S)),Darwin)
  PLATFORM := macos
else
  PLATFORM := windows
endif

ifneq (,$(filter arm64 aarch64,$(UNAME_M)))
  ARCH := arm64
else
  ARCH := x86_64
endif

# -- Rust target triples --------------------------------------------------------
TARGET_LINUX_X86_MUSL := x86_64-unknown-linux-musl
TARGET_LINUX_X86_GNU  := x86_64-unknown-linux-gnu
TARGET_LINUX_ARM_MUSL := aarch64-unknown-linux-musl
TARGET_LINUX_ARM_GNU  := aarch64-unknown-linux-gnu
TARGET_MACOS_ARM      := aarch64-apple-darwin
TARGET_MACOS_X86      := x86_64-apple-darwin
TARGET_WIN_X86_MSVC   := x86_64-pc-windows-msvc
TARGET_WIN_X86_GNU    := x86_64-pc-windows-gnu
TARGET_WIN_ARM_MSVC   := aarch64-pc-windows-msvc

# -- Formatting ---------------------------------------------------------------

fmt:
	$(CARGO) fmt --all -- --check

fmt-fix:
	$(CARGO) fmt --all

# -- Linting ------------------------------------------------------------------

lint:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

lint-fix:
	$(CARGO) clippy --workspace --all-targets --all-features --fix --allow-dirty --allow-staged -- -D warnings

# -- Documentation ------------------------------------------------------------

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --all-features

# -- Build --------------------------------------------------------------------

dev:
	$(CARGO) build --workspace --all-features

build:
	$(CARGO) build --workspace --profile release --all-features

# -- Check (type check only, no codegen) --------------------------------------

check:
	$(CARGO) check --workspace --all-targets --all-features

# -- Test ---------------------------------------------------------------------

test:
	$(CARGO) test --workspace --all-targets --all-features

# -- Supply chain audit -------------------------------------------------------

audit:
	$(CARGO) deny check

# -- Unused dependencies ------------------------------------------------------

machete:
	$(CARGO) machete

# -- Repository hygiene -------------------------------------------------------

hygiene:
	@echo "--- ASCII check (source files) ---"
	@! grep -rP '[\x80-\xFF]' src/ crates/ --include='*.rs' || { echo "FAIL: non-ASCII byte in source"; exit 1; }
	@echo "--- LF check (no CRLF) ---"
	@! grep -rP '\r' src/ crates/ --include='*.rs' || { echo "FAIL: CRLF line ending in source"; exit 1; }
	@echo "Hygiene OK"

# -- Full verification gate (run before every commit) -------------------------

check-all: fmt lint check test doc hygiene machete
	@echo ""
	@echo "================================================"
	@echo "  All checks passed."
	@echo "================================================"

# -- Cross-compilation --------------------------------------------------------

build-linux-x86-musl:
	$(CARGO) build --profile release --target $(TARGET_LINUX_X86_MUSL)

build-linux-x86-gnu:
	$(CARGO) build --profile release --target $(TARGET_LINUX_X86_GNU)

build-linux-arm-musl:
	$(CARGO) build --profile release --target $(TARGET_LINUX_ARM_MUSL)

build-linux-arm-gnu:
	$(CARGO) build --profile release --target $(TARGET_LINUX_ARM_GNU)

build-macos-arm:
	$(CARGO) build --profile release --target $(TARGET_MACOS_ARM)

build-macos-x86:
	$(CARGO) build --profile release --target $(TARGET_MACOS_X86)

build-macos-universal: build-macos-arm build-macos-x86
	mkdir -p $(DIST)
	lipo -create \
		target/$(TARGET_MACOS_ARM)/release/$(BIN) \
		target/$(TARGET_MACOS_X86)/release/$(BIN) \
		-output $(DIST)/$(BIN)-macos-universal

build-windows-x86-msvc:
	$(CARGO) build --profile release --target $(TARGET_WIN_X86_MSVC)

build-windows-x86-gnu:
	$(CARGO) build --profile release --target $(TARGET_WIN_X86_GNU)

build-windows-arm-msvc:
	$(CARGO) build --profile release --target $(TARGET_WIN_ARM_MSVC)

# -- Distribution artifacts ---------------------------------------------------

# `make dist` builds for the current platform only.
dist:
ifeq ($(PLATFORM),linux)
ifeq ($(ARCH),arm64)
	$(MAKE) build-linux-arm-musl
	mkdir -p $(DIST)
	cp target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64
else
	$(MAKE) build-linux-x86-musl
	mkdir -p $(DIST)
	cp target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-x86_64
endif
else ifeq ($(PLATFORM),macos)
	$(MAKE) build-macos-universal
else
	$(MAKE) build-windows-x86-msvc
	mkdir -p $(DIST)
	cp target/$(TARGET_WIN_X86_MSVC)/release/$(BIN).exe $(DIST)/$(BIN)-windows-x86_64.exe
endif

# `make dist-all` builds all 9 release targets (requires cross-compilation toolchains).
dist-all: build-linux-x86-musl build-linux-x86-gnu build-linux-arm-musl build-linux-arm-gnu build-macos-arm build-macos-x86 build-windows-x86-msvc build-windows-x86-gnu build-windows-arm-msvc
	mkdir -p $(DIST)
	cp target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-x86_64-musl
	cp target/$(TARGET_LINUX_X86_GNU)/release/$(BIN) $(DIST)/$(BIN)-linux-x86_64-gnu
	cp target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64-musl
	cp target/$(TARGET_LINUX_ARM_GNU)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64-gnu
	cp target/$(TARGET_MACOS_ARM)/release/$(BIN) $(DIST)/$(BIN)-macos-arm64
	cp target/$(TARGET_MACOS_X86)/release/$(BIN) $(DIST)/$(BIN)-macos-x86_64
	cp target/$(TARGET_WIN_X86_MSVC)/release/$(BIN).exe $(DIST)/$(BIN)-windows-x86_64.exe
	cp target/$(TARGET_WIN_X86_GNU)/release/$(BIN).exe $(DIST)/$(BIN)-windows-x86_64-gnu.exe
	cp target/$(TARGET_WIN_ARM_MSVC)/release/$(BIN).exe $(DIST)/$(BIN)-windows-arm64.exe
	cd $(DIST) && sha256sum ./* > SHA256SUMS

# -- Binary size report -------------------------------------------------------

size:
	@ls -lh $(DIST)/$(BIN)* 2>/dev/null || echo "No dist artifacts. Run 'make dist' first."

# -- Convenience --------------------------------------------------------------

fix: fmt-fix lint-fix

hooks:
	git config core.hooksPath .githooks

clean:
	$(CARGO) clean
	rm -rf $(DIST)
