# How to Create a Pure Static `minivtun` Binary

This guide explains how to compile a fully static `minivtun` executable using the provided unified build script. A static binary includes all its dependencies and can run on any Linux system of the same architecture without needing any libraries to be installed. This is ideal for creating portable tools or for deploying on minimal embedded systems.

The `build.sh` script automates the entire process:
- It downloads the appropriate `musl` C compiler toolchain (for native or cross-compilation).
- It downloads the `mbedtls` source code.
- It generates a minimal `mbedtls` configuration to reduce binary size.
- It compiles `mbedtls` as a static library for the specified target.
- It compiles `minivtun` and links it against the new static libraries.
- All dependencies and build artifacts are stored in the `build_deps` directory.

---

### Build Instructions

**Prerequisites:**
- `wget`
- `tar`
- `git` (used by the script to manage temporary file changes)
- A standard build environment (`make`, `gcc` for the host)

#### **1. Native Static Build (Default)**

This produces a static binary for the host `x86_64` architecture.

**Command:**
```bash
./build.sh
```
Or explicitly:
```bash
./build.sh native
```

**Verification:**
Once the script finishes, a target-specific binary is created.
```bash
file ./minivtun_x86_64
# Expected output:
# ./minivtun_x86_64: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped

ldd ./minivtun_x86_64
# Expected output:
#         not a dynamic executable
```

---

#### **2. Cross-Compilation for MIPS (e.g., Newifi 3 Router)**

This produces a static binary for `mipsel` routers. The script automatically applies the `-march=1004kc` flag to optimize for the Newifi 3's CPU.

**Command:**
```bash
./build.sh mipsel
```

**Verification:**
Check the resulting binary to confirm it's a MIPS executable.
```bash
file ./minivtun_mipsel
# Expected output:
# ./minivtun_mipsel: ELF 32-bit LSB pie executable, MIPS, MIPS32 rel2 version 1 (SYSV), static-pie linked, stripped
```

The resulting `minivtun_mipsel` binary is now ready to be copied to and executed on your MIPS-based router.
