# minivtun 编译指南

本文档提供minivtun的完整编译指南，包括动态链接、静态链接和交叉编译。

## 目录

- [快速开始](#快速开始)
- [编译选项](#编译选项)
- [加密后端选择](#加密后端选择)
- [静态编译](#静态编译)
- [交叉编译](#交叉编译)
- [故障排除](#故障排除)

---

## 快速开始

### 动态链接编译（推荐用于开发）

```bash
cd src
make                           # 使用OpenSSL（默认）
# 或
make CRYPTO_BACKEND=mbedtls    # 使用mbedtls
```

### 自动化静态编译（推荐用于生产环境）

```bash
./build.sh                     # x86_64静态编译
./build.sh mipsel              # MIPS交叉编译（路由器等）
```

---

## 编译选项

### 特性开关

所有Makefile都支持以下特性开关：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `WITH_IPV6` | yes | 启用IPv6支持 |
| `WITH_DAEMONIZE` | yes (src/Makefile)<br>no (Makefile.static) | 启用守护进程模式 |
| `WITH_CLIENT_MODE` | yes | 启用客户端模式 |
| `WITH_SERVER_MODE` | yes | 启用服务器模式 |
| `OPTIMIZE_FOR_SIZE` | no (src/Makefile)<br>yes (Makefile.static) | 优化二进制文件大小 |
| `NO_LOG` | no (src/Makefile)<br>yes (Makefile.static) | 禁用日志输出（最小化二进制） |

**示例：**
```bash
# 禁用IPv6和守护进程
make WITH_IPV6=no WITH_DAEMONIZE=no

# 最小化二进制
make OPTIMIZE_FOR_SIZE=yes NO_LOG=yes
```

---

## 加密后端选择

minivtun支持两种加密后端：

### OpenSSL（默认）

**特点：**
- 性能优秀，广泛使用
- 动态链接时无需额外配置
- 支持AES-128、AES-256、DES、DESX、RC4

**依赖：**
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# CentOS/RHEL
sudo yum install openssl-devel

# macOS
brew install openssl
```

**编译：**
```bash
make CRYPTO_BACKEND=openssl
```

### mbedtls

**特点：**
- 轻量级，适合嵌入式系统
- 代码体积小
- 静态链接友好

**依赖：**
```bash
# Ubuntu/Debian
sudo apt-get install libmbedtls-dev

# 或使用build.sh自动下载编译
```

**编译：**
```bash
make CRYPTO_BACKEND=mbedtls
```

**注意：** 系统的mbedtls版本可能存在API兼容性问题。对于生产环境，推荐使用`build.sh`自动编译mbedtls。

---

## 静态编译

静态编译生成的二进制文件包含所有依赖，可在任何Linux系统上运行。

### 方法1：使用build.sh（推荐）

`build.sh` 自动处理工具链下载、mbedtls编译和静态链接。

```bash
./build.sh              # 编译 x86_64 静态二进制
./build.sh mipsel       # 编译 MIPS 静态二进制（适用于路由器）
```

**生成的文件：**
- `minivtun_x86_64` - x86_64静态二进制
- `minivtun_mipsel` - MIPS静态二进制

**build.sh特性：**
- 自动下载musl工具链（无需系统依赖）
- 自动下载并编译mbedtls 3.1.0
- 启用LTO（链接时优化）和代码段清理
- 最小化配置（仅包含必需的加密模块）
- 所有依赖存储在`build_deps/`目录

**清理重新编译：**
```bash
rm -rf build_deps      # 清除所有依赖（强制重新下载编译）
./build.sh
```

### 方法2：使用Makefile.static（手动）

如果你已经有musl工具链和mbedtls：

```bash
make -f Makefile.static \
    CROSS_COMPILE=x86_64-linux-musl- \
    MBEDTLS_BASE=/path/to/mbedtls/install
```

**Makefile.static配置：**

```makefile
# 工具链配置
CROSS_COMPILE ?=                    # 交叉编译前缀（如 mipsel-linux-musl-）
TARGET_ARCH   ?= x86_64             # 目标架构

# mbedtls路径（自动检测）
MBEDTLS_BASE  ?= build_deps/install/$(TARGET_ARCH)
MBEDTLS_INC   ?= $(MBEDTLS_BASE)/include
MBEDTLS_LIB   ?= $(MBEDTLS_BASE)/lib

# 平台选择
PLATFORM      ?= linux              # linux 或 bsd
```

**链接器组（解决循环依赖）：**

mbedtls的静态库之间存在循环依赖，使用链接器组解决：

```makefile
LDLIBS := -L$(MBEDTLS_LIB) -Wl,--start-group -lmbedtls -lmbedx509 -lmbedcrypto -Wl,--end-group
```

---

## 交叉编译

### 使用build.sh（最简单）

```bash
./build.sh mipsel      # MIPS (MT7621等路由器)
```

### 手动交叉编译

**1. 安装交叉编译工具链：**

```bash
# 下载musl交叉编译工具链
wget https://musl.cc/mipsel-linux-musl-cross.tgz
tar -xzf mipsel-linux-musl-cross.tgz
export PATH=$PWD/mipsel-linux-musl-cross/bin:$PATH
```

**2. 编译mbedtls：**

```bash
wget https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.1.0.tar.gz
tar -xzf v3.1.0.tar.gz
cd mbedtls-3.1.0

# 创建最小化配置
cat > include/mbedtls/mbedtls_config.h <<EOF
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_AES_C
#define MBEDTLS_DES_C
#define MBEDTLS_MD5_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_MD_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_PKCS5_C

#endif
EOF

# 编译
cmake -B build \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=mips \
    -DCMAKE_C_COMPILER=mipsel-linux-musl-gcc \
    -DCMAKE_C_FLAGS="-Os -march=1004kc -flto -ffunction-sections -fdata-sections" \
    -DCMAKE_INSTALL_PREFIX=/path/to/install \
    -DENABLE_TESTING=OFF \
    -DENABLE_PROGRAMS=OFF \
    -DUSE_STATIC_MBEDTLS_LIBRARY=ON

cmake --build build --target install
```

**3. 编译minivtun：**

```bash
make -f Makefile.static \
    CROSS_COMPILE=mipsel-linux-musl- \
    MBEDTLS_BASE=/path/to/install \
    EXTRA_CFLAGS="-march=1004kc"
```

### 支持的架构

build.sh当前支持：
- **x86_64** (native) - 服务器、台式机
- **mipsel** - MIPS路由器（如Newifi 3, MT7621等）

添加新架构：修改`build.sh`中的target配置部分。

---

## 故障排除

### 1. mbedtls链接错误

**问题：**
```
undefined reference to 'mbedtls_md_init'
undefined reference to 'mbedtls_pkcs5_pbkdf2_hmac'
```

**原因：** mbedtls配置缺少必需模块。

**解决：**
确保mbedtls配置包含以下模块：
```c
#define MBEDTLS_MD_C        // 消息摘要框架
#define MBEDTLS_SHA224_C    // SHA224 (SHA256依赖)
#define MBEDTLS_SHA256_C    // SHA256
#define MBEDTLS_PKCS5_C     // PBKDF2
```

使用`build.sh`会自动生成正确配置。如手动编译，参考上述手动交叉编译步骤。

### 2. 链接器循环依赖错误

**问题：**
```
undefined reference to symbols in libmbedcrypto
```

**原因：** 静态链接时库的顺序问题。

**解决：**
使用链接器组（Makefile.static已包含）：
```makefile
LDLIBS := -Wl,--start-group -lmbedtls -lmbedx509 -lmbedcrypto -Wl,--end-group
```

### 3. LTO版本不匹配警告

**问题：**
```
warning: using LTO version 11.2 for object built with 12.0
```

**原因：** 不同版本的gcc编译的.o文件和.a库混用。

**解决：**
- 清理并重新编译：`rm -rf build_deps && ./build.sh`
- 或忽略该警告（不影响功能）

### 4. OpenSSL动态链接失败

**问题：**
```
error while loading shared libraries: libcrypto.so.x
```

**解决：**
```bash
# 安装OpenSSL开发库
sudo apt-get install libssl-dev

# 或使用静态编译
./build.sh
```

### 5. SHA256/SHA224配置错误

**问题：**
```
error: MBEDTLS_SHA256_C defined without MBEDTLS_SHA224_C
```

**原因：** mbedtls 3.x要求SHA256和SHA224同时启用。

**解决：**
确保mbedtls配置同时定义：
```c
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
```

### 6. 交叉编译工具链问题

**问题：**
```
command not found: mipsel-linux-musl-gcc
```

**解决：**
```bash
# 确保工具链在PATH中
export PATH=/path/to/toolchain/bin:$PATH

# 或使用build.sh自动下载
./build.sh mipsel
```

---

## 构建产物

### src/Makefile（动态链接）
- **输出：** `src/minivtun`
- **特点：** 依赖系统加密库，体积小，调试友好
- **用途：** 开发、测试

### Makefile.static（静态链接）
- **输出：** `minivtun`
- **特点：** 无外部依赖，体积较大
- **用途：** 生产部署、嵌入式设备

### build.sh（自动化静态编译）
- **输出：** `minivtun_x86_64`, `minivtun_mipsel`
- **特点：** 完全自动化，包含所有依赖
- **用途：** 生产环境一键编译

---

## 编译配置摘要

| 功能 | src/Makefile | Makefile.static | build.sh |
|------|--------------|-----------------|----------|
| 链接方式 | 动态 | 静态 | 静态 |
| 工具链 | 系统gcc | 可配置 | 自动下载musl |
| mbedtls | 系统库 | 手动指定 | 自动编译 |
| 交叉编译 | 需手动配置 | 支持 | 自动化 |
| LTO优化 | 否 | 是 | 是 |
| 代码段清理 | 可选 | 是 | 是 |
| 适用场景 | 开发/测试 | 高级用户 | 生产部署 |

---

## 推荐工作流

**开发阶段：**
```bash
cd src
make CRYPTO_BACKEND=openssl
./minivtun -h
```

**测试阶段：**
```bash
make -f Makefile.static clean
make -f Makefile.static
```

**生产部署：**
```bash
./build.sh
scp minivtun_x86_64 user@server:/usr/local/sbin/minivtun
```

**路由器部署：**
```bash
./build.sh mipsel
scp minivtun_mipsel root@router:/usr/bin/minivtun
```

---

## 相关文档

- [静态编译详解](COMPILING_STATIC.md) - 深入了解静态编译细节
- [编译问题说明](编译问题说明.md) - 常见编译问题汇总
- [使用指南](../usage/USAGE_GUIDE_CN.md) - 编译后的使用方法

---

**最后更新：** 2026-01-22
