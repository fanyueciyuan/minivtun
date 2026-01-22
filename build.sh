#!/bin/bash
set -e # Exit on any error

#
# build.sh
#
# A unified script to build minivtun statically for multiple architectures.
#
# Usage:
#   ./build.sh [TARGET]
#
# TARGETS:
#   native (default) - Builds a static binary for the host x86_64 architecture.
#   mipsel           - Cross-compiles a static binary for MIPS (e.g., Newifi 3 router).
#
# This script handles downloading the required toolchain and mbedtls, compiling
# them from source, and then building the final minivtun executable. All
# dependencies are stored in the 'build_deps' directory.
#

# --- Base Configuration ---
TARGET="${1:-native}" # Default to 'native' if no argument is given
SCRIPT_DIR=$(pwd)
DEPS_DIR="${SCRIPT_DIR}/build_deps"

MBEDTLS_VERSION="3.1.0"
MBEDTLS_URL="https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${MBEDTLS_VERSION}.tar.gz"
MBEDTLS_SRC_DIR="${DEPS_DIR}/src/mbedtls-${MBEDTLS_VERSION}"


# --- Target-Specific Configuration ---
EXTRA_CFLAGS=""
if [ "$TARGET" = "native" ] || [ "$TARGET" = "x86_64" ]; then
    echo "--- Configuring for NATIVE (x86_64) build ---"
    TARGET_NAME="x86_64"
    ARCH_SUFFIX="native"
    TARGET_ARCH="x86_64-linux-musl"
    CROSS_COMPILE_PREFIX=""
    CPU_ARCH_FLAG=""
    CMAKE_TOOLCHAIN_ARGS=""

elif [ "$TARGET" = "mipsel" ]; then
    echo "--- Configuring for MIPS (mipsel) cross-compilation ---"
    TARGET_NAME="mipsel"
    ARCH_SUFFIX="cross"
    TARGET_ARCH="mipsel-linux-musl"
    CROSS_COMPILE_PREFIX="${TARGET_ARCH}-"
    CPU_ARCH_FLAG="-march=1004kc"
    EXTRA_CFLAGS=$CPU_ARCH_FLAG
    # Arguments for CMake to correctly identify the target system
    CMAKE_TOOLCHAIN_ARGS="-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=mips"

else
    echo "Error: Unknown target '$TARGET'."
    echo "Usage: $0 [native|mipsel]"
    exit 1
fi


# --- Derived Paths ---
TOOLCHAIN_BASE_DIR="${DEPS_DIR}/toolchains"
TOOLCHAIN_URL="https://musl.cc/${TARGET_ARCH}-${ARCH_SUFFIX}.tgz"
TOOLCHAIN_ARCHIVE="${TOOLCHAIN_BASE_DIR}/${TARGET_ARCH}-${ARCH_SUFFIX}.tgz"
TOOLCHAIN_EXTRACT_DIR="${TARGET_ARCH}-${ARCH_SUFFIX}"
TOOLCHAIN_DIR="${TOOLCHAIN_BASE_DIR}/${TOOLCHAIN_EXTRACT_DIR}"

INSTALL_BASE_DIR="${DEPS_DIR}/install"
MBEDTLS_INSTALL_DIR="${INSTALL_BASE_DIR}/${TARGET_NAME}"
FINAL_BINARY_NAME="minivtun_${TARGET_NAME}"

# --- Script Body ---

echo "--- Preparing build environment for target: ${TARGET_NAME} ---"
mkdir -p "$DEPS_DIR/src" "$TOOLCHAIN_BASE_DIR" "$INSTALL_BASE_DIR"

# Clean any previous installation for this target
rm -rf "$MBEDTLS_INSTALL_DIR"

# --- Toolchain Setup ---
if [ ! -d "$TOOLCHAIN_DIR" ]; then
    echo "--- Downloading and setting up ${TARGET_ARCH} toolchain ---"
    mkdir -p "$(dirname "$TOOLCHAIN_ARCHIVE")"
    wget --no-check-certificate -O "$TOOLCHAIN_ARCHIVE" "$TOOLCHAIN_URL"
    tar -xzf "$TOOLCHAIN_ARCHIVE" -C "$TOOLCHAIN_BASE_DIR"
    rm "$TOOLCHAIN_ARCHIVE"
else
    echo "--- ${TARGET_ARCH} toolchain already present ---"
fi

# Set environment for the rest of the script
export PATH="${TOOLCHAIN_DIR}/bin:${PATH}"
export CC="${CROSS_COMPILE_PREFIX}gcc"

# --- mbedtls Dependency Setup ---
if [ ! -d "$MBEDTLS_SRC_DIR" ]; then
    echo "--- Downloading mbedtls v${MBEDTLS_VERSION} source ---"
    wget --no-check-certificate -qO- "$MBEDTLS_URL" | tar -xz -C "${DEPS_DIR}/src"
else
    echo "--- mbedtls source already present ---"
fi

echo "--- Generating minimal mbedtls config ---"
cat > "${MBEDTLS_SRC_DIR}/include/mbedtls/mbedtls_config.h" <<EOL
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// System Support
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_NO_PLATFORM_ENTROPY

// Modules Required by minivtun
#define MBEDTLS_AES_C
#define MBEDTLS_DES_C
#define MBEDTLS_MD5_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC

// HMAC and PBKDF2 support (required for authentication)
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_PKCS5_C

#endif /* MBEDTLS_CONFIG_H */
EOL

echo "--- Building and installing mbedtls for ${TARGET_NAME} ---"
cd "$MBEDTLS_SRC_DIR"
rm -rf build # Clean previous build

cmake -B build \
    ${CMAKE_TOOLCHAIN_ARGS} \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="-Os -flto -ffunction-sections -fdata-sections -fPIC ${CPU_ARCH_FLAG}" \
    -DCMAKE_INSTALL_PREFIX="$MBEDTLS_INSTALL_DIR" \
    -DENABLE_TESTING=OFF \
    -DENABLE_PROGRAMS=OFF \
    -DUSE_STATIC_MBEDTLS_LIBRARY=ON

cmake --build build --target install
cd "$SCRIPT_DIR"

echo "--- Building minivtun statically for ${TARGET_NAME} ---"

make -f Makefile.static clean >/dev/null 2>&1

# Build minivtun, passing toolchain and library paths to the Makefile
# The CFLAGS variable is passed directly to make, which appends it to the existing CFLAGS
make -f Makefile.static \
    CROSS_COMPILE="${CROSS_COMPILE_PREFIX}" \
    MBEDTLS_BASE="${MBEDTLS_INSTALL_DIR}" \
    EXTRA_CFLAGS="${EXTRA_CFLAGS}"

# Rename the final binary to be target-specific
mv minivtun "$FINAL_BINARY_NAME"

echo ""
echo "--- Static build for ${TARGET_NAME} complete! ---"
echo "Binary created:"
ls -lh "$FINAL_BINARY_NAME"
file "$FINAL_BINARY_NAME"
