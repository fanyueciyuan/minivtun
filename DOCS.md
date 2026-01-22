# minivtun 项目文档索引

欢迎查阅minivtun的完整文档。本页面提供所有文档的导航和概览。

---

## 📚 文档分类

### 🔨 编译文档 (docs/build/)

| 文档 | 说明 | 适用人群 |
|------|------|----------|
| [BUILD.md](build/BUILD.md) | 完整编译指南，包含动态链接、静态链接和交叉编译 | 所有用户 ⭐ |
| [COMPILING_STATIC.md](build/COMPILING_STATIC.md) | 静态编译详细说明 | 高级用户 |
| [编译问题说明.md](build/编译问题说明.md) | 常见编译问题和解决方案 | 故障排除 |

**推荐阅读顺序：**
1. 新用户：先读 BUILD.md 快速开始部分
2. 遇到问题：查看 编译问题说明.md
3. 深入了解：阅读 COMPILING_STATIC.md

### 🔒 安全文档 (docs/security/)

| 文档 | 说明 | 重要性 |
|------|------|--------|
| [ENCRYPTION_DESIGN.md](security/ENCRYPTION_DESIGN.md) | 加密设计问题分析和解决方案 | ⭐⭐⭐ |
| [HMAC完整修复指南.md](security/HMAC完整修复指南.md) | HMAC功能实现和修复步骤 | ⭐⭐ |
| [HMAC安全审计报告.md](security/HMAC安全审计报告.md) | 安全审计结果 | ⭐⭐ |
| [HMAC漏洞执行摘要.md](security/HMAC漏洞执行摘要.md) | 漏洞概述和影响 | ⭐ |
| [HMAC问题图解.md](security/HMAC问题图解.md) | 问题可视化说明 | ⭐ |
| [HMAC调试指南.md](security/HMAC调试指南.md) | 调试工具和方法 | 开发者 |
| [HMAC修复方案.md](security/HMAC修复方案.md) | 修复方案对比 | 架构师 |
| [README_HMAC_FIXES.md](security/README_HMAC_FIXES.md) | HMAC修复总览 | 快速参考 |
| [修复完成-测试指南.md](security/修复完成-测试指南.md) | 修复后测试步骤 | 测试人员 |

**核心安全文档：**
- **必读：** ENCRYPTION_DESIGN.md - 理解加密设计的核心问题
- **开发者：** HMAC完整修复指南.md - 实现细节
- **审计：** HMAC安全审计报告.md - 安全评估

### 📖 使用文档 (docs/usage/)

| 文档 | 说明 | 用途 |
|------|------|------|
| [USAGE_GUIDE_CN.md](usage/USAGE_GUIDE_CN.md) | 完整使用指南（中文） | 用户手册 ⭐ |
| [测试指南.md](usage/测试指南.md) | 功能测试方法 | 测试 |
| [完整测试指南.md](usage/完整测试指南.md) | 详细测试流程 | 全面测试 |
| [TUN协议错误修复.md](usage/TUN协议错误修复.md) | TUN设备常见问题 | 故障排除 |
| [新设备恢复指南.md](usage/新设备恢复指南.md) | 在新设备上部署minivtun | 部署 |

**使用流程：**
1. 编译完成后阅读 USAGE_GUIDE_CN.md
2. 测试时参考 测试指南.md
3. 遇到TUN设备问题查看 TUN协议错误修复.md

---

## 🚀 快速导航

### 我是新用户

1. **开始编译：** [BUILD.md](build/BUILD.md) - 快速开始部分
2. **运行程序：** [USAGE_GUIDE_CN.md](usage/USAGE_GUIDE_CN.md)
3. **遇到问题：** [编译问题说明.md](build/编译问题说明.md)

### 我是开发者

1. **了解架构：** [ENCRYPTION_DESIGN.md](security/ENCRYPTION_DESIGN.md)
2. **安全实现：** [HMAC完整修复指南.md](security/HMAC完整修复指南.md)
3. **静态编译：** [BUILD.md](build/BUILD.md) - 静态编译部分

### 我在排查问题

1. **编译错误：** [编译问题说明.md](build/编译问题说明.md)
2. **连接问题：** [USAGE_GUIDE_CN.md](usage/USAGE_GUIDE_CN.md) - 故障排除
3. **TUN设备：** [TUN协议错误修复.md](usage/TUN协议错误修复.md)
4. **HMAC验证失败：** [HMAC调试指南.md](security/HMAC调试指南.md)

### 我需要部署

1. **编译二进制：** `./build.sh` (参考 [BUILD.md](build/BUILD.md))
2. **服务器部署：** [新设备恢复指南.md](usage/新设备恢复指南.md)
3. **配置使用：** [USAGE_GUIDE_CN.md](usage/USAGE_GUIDE_CN.md)
4. **测试验证：** [测试指南.md](usage/测试指南.md)

---

## 📋 主要特性文档

### 加密和认证

- **加密算法：** AES-128/256-CBC, DES, DESX, RC4
- **认证方式：** HMAC-SHA256（16字节）
- **密钥派生：** PBKDF2-SHA256（100,000迭代）
- **设计文档：** [ENCRYPTION_DESIGN.md](security/ENCRYPTION_DESIGN.md)

### 编译选项

- **加密后端：** OpenSSL, mbedtls
- **链接方式：** 动态链接, 静态链接
- **交叉编译：** x86_64, MIPS
- **完整说明：** [BUILD.md](build/BUILD.md)

### 协议特性

- **隧道协议：** 基于UDP的TUN隧道
- **IPv4/IPv6：** 双栈支持
- **消息类型：** ECHO、IPDATA
- **协议详情：** [USAGE_GUIDE_CN.md](usage/USAGE_GUIDE_CN.md)

---

## 🔍 按主题查找

### 编译相关

- [x86_64静态编译](build/BUILD.md#使用buildsh推荐) - 使用build.sh
- [MIPS交叉编译](build/BUILD.md#交叉编译) - 路由器等嵌入式设备
- [mbedtls后端](build/BUILD.md#mbedtls) - 轻量级加密库
- [链接器问题](build/BUILD.md#2-链接器循环依赖错误) - 解决undefined reference

### 安全相关

- [密文损坏问题](security/ENCRYPTION_DESIGN.md#问题详情) - 根本原因分析
- [不加密Header方案](security/ENCRYPTION_DESIGN.md#已实现解决方案不加密header) - 当前实现
- [AEAD模式](security/ENCRYPTION_DESIGN.md#方案2-aead模式未来考虑) - 未来改进
- [安全审计](security/HMAC安全审计报告.md) - 完整审计报告

### 使用相关

- [服务器配置](usage/USAGE_GUIDE_CN.md) - 监听地址、端口
- [客户端配置](usage/USAGE_GUIDE_CN.md) - 连接服务器
- [TUN设备配置](usage/USAGE_GUIDE_CN.md) - IP地址、路由
- [常见错误](usage/TUN协议错误修复.md) - 错误代码解释

---

## 📝 文档版本历史

### v2.0 (2026-01-22) - 当前版本

**重大更新：**
- ✅ 修复HMAC加密设计缺陷
- ✅ 实现"只加密payload"方案
- ✅ 支持mbedtls 3.1.0
- ✅ 完善build.sh自动化编译
- ✅ 添加链接器组解决静态链接问题

**新增文档：**
- BUILD.md - 统一编译指南
- ENCRYPTION_DESIGN.md - 加密设计详解
- 多个HMAC相关安全文档

**文档重组：**
- 建立docs/目录结构
- 分类为build/、security/、usage/
- 创建文档索引（本文件）

### v1.x (2026-01之前)

- 基础功能实现
- OpenSSL后端支持
- 基本文档

---

## 🛠️ 开发文档

### 代码结构

```
minivtun/
├── src/
│   ├── minivtun.c          # 主程序
│   ├── client.c            # 客户端逻辑
│   ├── server.c            # 服务器逻辑
│   ├── crypto_openssl.c    # OpenSSL加密后端
│   ├── crypto_mbedtls.c    # mbedtls加密后端
│   ├── platform_linux.c    # Linux平台支持
│   └── library.c           # 工具函数
├── Makefile.static         # 静态编译Makefile
├── build.sh                # 自动化编译脚本
└── docs/                   # 文档目录
    ├── build/              # 编译文档
    ├── security/           # 安全文档
    └── usage/              # 使用文档
```

### 关键文件

| 文件 | 功能 | 修改频率 |
|------|------|----------|
| `src/crypto_*.c` | 加密实现 | 中 |
| `src/client.c` | 客户端HMAC计算 | 低 |
| `src/server.c` | 服务器HMAC验证 | 低 |
| `Makefile.static` | 静态编译配置 | 低 |
| `build.sh` | 自动化编译 | 中 |

### 加密实现细节

参见：[ENCRYPTION_DESIGN.md](security/ENCRYPTION_DESIGN.md#代码实现)

---

## 🔗 外部资源

### 官方资源

- **GitHub仓库：** https://github.com/rssnsj/minivtun
- **原作者：** Justin Liu (rssnsj@gmail.com)

### 相关技术

- **OpenSSL：** https://www.openssl.org/
- **mbedtls：** https://github.com/Mbed-TLS/mbedtls
- **PBKDF2：** [RFC 2898](https://tools.ietf.org/html/rfc2898)
- **HMAC：** [RFC 2104](https://tools.ietf.org/html/rfc2104)
- **TUN/TAP：** [Linux Kernel Documentation](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)

### 工具链

- **musl-cross-make：** https://musl.cc/
- **交叉编译工具：** https://github.com/richfelker/musl-cross-make

---

## 📞 获取帮助

### 文档问题

如果文档不清楚或有错误，请：
1. 查看相关的其他文档
2. 参考代码注释
3. 提交Issue报告问题

### 技术问题

1. **编译问题：** 查看 [编译问题说明.md](build/编译问题说明.md)
2. **使用问题：** 查看 [USAGE_GUIDE_CN.md](usage/USAGE_GUIDE_CN.md)
3. **安全问题：** 查看 [HMAC调试指南.md](security/HMAC调试指南.md)

### 贡献文档

欢迎改进文档！提交Pull Request时：
- 保持文档结构一致
- 添加清晰的示例
- 更新本索引文件
- 注明最后更新日期

---

## 📌 常见问题快速链接

| 问题 | 解决方案 |
|------|----------|
| 如何编译？ | [BUILD.md](build/BUILD.md) |
| undefined reference to mbedtls_* | [BUILD.md#1-mbedtls链接错误](build/BUILD.md#1-mbedtls链接错误) |
| HMAC验证失败 | [HMAC调试指南.md](security/HMAC调试指南.md) |
| 解密后opcode错误 | [ENCRYPTION_DESIGN.md](security/ENCRYPTION_DESIGN.md#失败原因) |
| SHA256配置错误 | [BUILD.md#5-sha256sha224配置错误](build/BUILD.md#5-sha256sha224配置错误) |
| 如何交叉编译MIPS？ | [BUILD.md#交叉编译](build/BUILD.md#交叉编译) |
| TUN设备权限问题 | [TUN协议错误修复.md](usage/TUN协议错误修复.md) |
| 如何测试连接？ | [测试指南.md](usage/测试指南.md) |

---

**文档维护：** minivtun团队
**最后更新：** 2026-01-22
**文档版本：** 2.0

---

**返回：** [README.md](../README.md)
