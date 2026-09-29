# NOMAD Build System for Server Development
# ==========================================
# This Makefile provides targets for developing and building the NOMAD project,
# including kernel compilation, userspace server development, and ISO creation.

# Variables
# ---------

CARGO = cargo
CARGO_TARGET = x86_64-unknown-none
KERNEL_NAME = cintos_kernel
BUILD_DIR = target/$(CARGO_TARGET)
USERSPACE_DIR = userspace/cintos_user
ISO_OUT = cintos.iso

# Directories
KERNEL_SRC = src
KERNEL_BUILD = $(KERNEL_SRC)
USERSPACE_BUILD = $(USERSPACE_DIR)

# Default target
.PHONY: all
all: help

# Help target
.PHONY: help
help:
        @echo "NOMAD Build System"
        @echo "==================="
        @echo ""
        @echo "Targets available:"
        @echo "  help          - Show this help message"
        @echo "  build-kernel  - Build the kernel only"
        @echo "  build-userspace - Build userspace libraries and servers"
        @echo "  build-all     - Build both kernel and userspace"
        @echo "  build-iso     - Build the bootable ISO"
        @echo "  build-servers - Build all userspace servers"
        @echo "  run-servers   - Build servers and run them (if possible)"
        @echo "  clean         - Clean build artifacts"
        @echo "  tests         - Run tests for kernel and userspace"
        @echo "  fmt           - Format code with rustfmt"
        @echo "  check         - Check code with clippy"
        @echo ""
        @echo "Examples:"
        @echo "  make build-kernel    # Build just the kernel"
        @echo "  make build-servers   # Build all servers (init, ipc, timer, etc.)"
        @echo "  make build-iso       # Create the bootable ISO"

# Build kernel only
.PHONY: build-kernel
build-kernel:
        @echo "Building kernel..."
        $(CARGO) build --target $(CARGO_TARGET)

# Build userspace only
.PHONY: build-userspace
build-userspace:
        @echo "Building userspace..."
        cd $(USERSPACE_DIR) && $(CARGO) build --target $(CARGO_TARGET)

# Build both kernel and userspace
.PHONY: build-all
build-all: build-kernel build-userspace

# Build all userspace servers (the actual binary executables)
.PHONY: build-servers
build-servers: build-userspace
        @echo "Building userspace servers..."
        $(CARGO) build --target $(CARGO_TARGET) --bin init
        $(CARGO) build --target $(CARGO_TARGET) --bin ipc_sender
        $(CARGO) build --target $(CARGO_TARGET) --bin ipc_receiver
        $(CARGO) build --target $(CARGO_TARGET) --bin timer_server
        $(CARGO) build --target $(CARGO_TARGET) --bin shm_sender
        $(CARGO) build --target $(CARGO_TARGET) --bin shm_receiver
        $(CARGO) build --target $(CARGO_TARGET) --bin mt_test
        $(CARGO) build --target $(CARGO_TARGET) --bin mt_waker
        $(CARGO) build --target $(CARGO_TARGET) --bin fault_keeper
        $(CARGO) build --target $(CARGO_TARGET) --bin fault_child

# Run servers (build first, then try to run if environment supports)
.PHONY: run-servers
run-servers: build-servers
        @echo "Servers built successfully"
        @echo "Note: To run servers, you need to:"
        @echo "  1. Have a proper environment with QEMU/VMware/etc."
        @echo "  2. Build and run the ISO with: make build-iso && qemu-system-x86_64 -cdrom cintos.iso"
        @echo "  See README for more details"

# Build ISO (via scripts/build_iso.sh: cargo build + C-демо + OSABI
# патч + xorriso + limine bios-install)
.PHONY: build-iso
build-iso:
        @echo "Building ISO..."
        $(SHELL) scripts/build_iso.sh
        @echo "ISO build completed. Check $(ISO_OUT) in the workspace root."

# Clean build artifacts
.PHONY: clean
clean:
        @echo "Cleaning build artifacts..."
        $(CARGO) clean
        @echo "Clean completed."

# Run tests
.PHONY: tests
tests:
        @echo "Running tests..."
        $(CARGO) test --target $(CARGO_TARGET)
        cd $(USERSPACE_DIR) && $(CARGO) test --target $(CARGO_TARGET)

# Format code
.PHONY: fmt
fmt:
        @echo "Formatting code..."
        $(CARGO) fmt
        cd $(USERSPACE_DIR) && $(CARGO) fmt

# Check code
.PHONY: check
check:
        @echo "Checking code with clippy..."
        $(CARGO) clippy --target $(CARGO_TARGET)
        cd $(USERSPACE_DIR) && $(CARGO) clippy --target $(CARGO_TARGET)

# Quick build status check
.PHONY: status
status:
        @echo "Build status:"
        @if [ -d "$(BUILD_DIR)" ]; then \
          echo "Kernel build directory exists:"; \
          ls -la $(BUILD_DIR)/; \
        else \
          echo "Kernel not yet built"; \
        fi
        @if [ -d "$(USERSPACE_DIR)/target/$(CARGO_TARGET)" ]; then \
          echo ""; echo "Userspace build directory exists:"; \
          ls -la $(USERSPACE_DIR)/target/$(CARGO_TARGET)/; \
        else \
          echo ""; echo "Userspace not yet built"; \
        fi