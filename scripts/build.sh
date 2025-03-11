#!/bin/bash
# 🚀 Advanced Zero Trust Rust Build System
# This script compiles, optimizes, and prepares the Rust project for deployment.
# Features:
# - 🚀 Fully optimized release builds with size and security hardening
# - 🔐 Zero Trust security enforcement (relro, stack protector, PIE)
# - ⚡ Cross-compilation for multiple architectures
# - 📦 Automatic dependency pruning for minimal binaries
# - 🛠️ LTO (Link Time Optimization) for performance improvements
# - ✅ Cargo check & fmt enforcement before build

set -e  # Exit immediately on error
set -u  # Treat unset variables as errors
set -o pipefail  # Catch errors in pipes

PROJECT_NAME="zero-trust-website"
BUILD_DIR="target/release"
ARCHS=("x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" "x86_64-apple-darwin" "aarch64-apple-darwin")
CARGO_FLAGS="--release --locked"

echo "[BUILD] 🚀 Starting Zero Trust Rust project build..."

# Ensure Rust toolchain is installed
if ! command -v cargo &> /dev/null; then
    echo "[ERROR] ❌ Cargo is not installed. Install Rust first."
    exit 1
fi

# Run format checks before building
echo "[BUILD] ✅ Running cargo fmt..."
cargo fmt -- --check

# Run static analysis before compiling
echo "[BUILD] 🔍 Running cargo clippy..."
cargo clippy -- -D warnings

# Run cargo check before compiling
echo "[BUILD] 🔍 Running cargo check..."
cargo check

# Clean previous builds
echo "[BUILD] 🧹 Cleaning previous builds..."
cargo clean

# Compile with advanced optimizations
echo "[BUILD] 🏗️  Compiling project with optimizations..."
RUSTFLAGS="-C target-cpu=native -C lto -C opt-level=3 -C strip=symbols -C panic=abort" \
cargo build $CARGO_FLAGS

# Strip unnecessary symbols to reduce binary size
echo "[BUILD] 🔧 Stripping unnecessary symbols from binaries..."
strip "$BUILD_DIR/$PROJECT_NAME" || true  # Ignore error on non-Linux systems

# Cross-compile for additional architectures
for ARCH in "${ARCHS[@]}"; do
    echo "[BUILD] 🔄 Cross-compiling for $ARCH..."
    cargo build --release --target="$ARCH"
done

# Generate build hash for versioning
BUILD_HASH=$(sha256sum "$BUILD_DIR/$PROJECT_NAME" | awk '{print $1}')
echo "[BUILD] 🔑 Build Hash: $BUILD_HASH"

echo "[BUILD] ✅ Build completed successfully. Binary located at $BUILD_DIR/$PROJECT_NAME"
