# Encryption Design Issue and Solution

## 问题概述

minivtun在实现HMAC认证时遇到了一个严重的设计问题：加密整个消息后，用HMAC覆盖auth_key字段会破坏密文，导致解密失败。

---

## 问题详情

### 消息结构

```c
struct minivtun_msg {
    struct {
        __u8 opcode;           // offset 0
        __u8 rsv;              // offset 1
        __be16 seq;            // offset 2-3
        __u8 auth_key[16];     // offset 4-19
    } hdr;  // 20 bytes total (MINIVTUN_MSG_BASIC_HLEN)

    union {
        struct { ... } ipdata;
        struct { ... } echo;
    };
}
```

### 原始设计的问题流程

**客户端发送：**
1. 构建消息，auth_key字段清零
2. 加密**整个消息**（包括header + payload）→ 生成密文
3. 密文的offset 4-19位置现在包含加密后的数据
4. 将offset 4-19清零 ❌ **破坏密文**
5. 计算HMAC（对清零后的密文）
6. 将HMAC写入offset 4-19
7. 发送

**服务器接收：**
1. 接收消息：offset 4-19包含HMAC，其余是密文
2. 提取offset 4-19的HMAC
3. 将offset 4-19清零
4. 计算HMAC并验证 ✓ 验证成功
5. 尝试解密... **但密文已损坏！** ❌
6. 解密损坏的密文 → **输出垃圾数据** ❌

### 失败原因

在CBC模式下，修改密文字节会影响解密：
- 修改第N个块会影响第N和第N+1个块的解密
- auth_key位于offset 4-19（跨越块0和块1）
- 丢失这16字节密文使得无法正确解密：
  - 块0（offset 0-15）：包含opcode、rsv、seq和部分auth_key
  - 用错误数据解密offset 4-15会产生垃圾opcode

**结果：** 服务器看到随机opcode如0xf9、0x4a、0xd9，而不是正确的0x00（ECHO_REQ）

### 调试过程发现

1. **密钥派生错误（已修复）：** HMAC密钥从错误的偏移量提取
   - 错误：`key_material + 32`（固定偏移）
   - 正确：`key_material + ctx->enc_key_len`（动态偏移）

2. **HMAC计算不一致（已修复）：** 发送方和接收方计算HMAC时auth_key状态不同

3. **根本问题：密文损坏（本文档重点）**

---

## 解决方案对比

### 方案1: 不加密Header（已采用）✓

**设计思路：**
- 只加密payload，header保持明文
- Header（opcode、rsv、seq、auth_key）以明文发送
- HMAC覆盖整个消息（明文header + 加密payload）
- auth_key字段纯粹用于存储HMAC

**优点：**
- 实现简单
- 无密文损失
- Header字段（opcode、seq）无需解密即可访问
- 符合许多协议的标准做法
- 性能开销小

**缺点：**
- Header元数据对攻击者可见
- 序列号可见（但不算关键信息）

**安全性分析：**
- ✓ **机密性：** Payload加密
- ✓ **完整性：** HMAC保护整个消息
- ✓ **认证性：** HMAC提供身份验证
- ✓ **防重放：** 序列号在header中
- ✓ **Header暴露：** 对此协议可接受（opcode、seq非敏感）

### 方案2: AEAD模式（未来考虑）

**设计思路：**
- 从AES-CBC切换到AES-GCM
- 支持关联数据（header）：认证但不加密
- 现代、安全的方法

**优点：**
- 最佳安全性
- 行业标准
- 内置认证（无需单独HMAC）
- 防止填充攻击

**缺点：**
- 需要OpenSSL 1.0.1+或mbedtls支持
- 代码改动较大
- 不同的IV/nonce处理方式
- 向后兼容性问题

### 方案3: 重新设计消息格式（已放弃）

**设计思路：**
- 将auth_key移到加密区域外
- 需要协议版本升级
- 破坏兼容性

**缺点：**
- 改动最大
- 兼容性问题严重
- 需要维护多个协议版本

---

## 已实现解决方案：不加密Header

### 新的消息处理流程

**客户端发送：**
```
1. 构建消息：header（opcode, rsv, seq, auth_key=0）+ payload
2. 只加密payload（跳过20字节header）→ encrypted_payload
3. 构建最终消息：header（明文）+ encrypted_payload
4. 将auth_key字段清零（已经是0）
5. 计算整个消息的HMAC
6. 将HMAC写入auth_key字段
7. 发送
```

**服务器接收：**
```
1. 接收消息
2. 从auth_key字段提取HMAC
3. 将auth_key字段清零
4. 计算HMAC并验证 ✓
5. 无需恢复任何数据 - header从未被加密！
6. 只解密payload ✓
7. 处理消息，opcode正确 ✓
```

### 代码实现

#### 1. crypto_encrypt() 修改

**OpenSSL和mbedtls共同逻辑：**

```c
int crypto_encrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
{
    if (!c_ctx) {
        memmove(out, in, *dlen);
        return 0;
    }

    const size_t HEADER_SIZE = 20;  // MINIVTUN_MSG_BASIC_HLEN

    if (*dlen < HEADER_SIZE) {
        memmove(out, in, *dlen);
        return 0;
    }

    // 复制header为明文
    memcpy(out, in, HEADER_SIZE);

    // 只加密payload部分
    size_t payload_len = *dlen - HEADER_SIZE;
    if (payload_len == 0) {
        return 0;
    }

    void* payload_in = (unsigned char*)in + HEADER_SIZE;
    void* payload_out = (unsigned char*)out + HEADER_SIZE;

    // ... 加密payload_in到payload_out ...

    *dlen = HEADER_SIZE + encrypted_payload_len;
    return 0;
}
```

#### 2. crypto_decrypt() 修改

```c
int crypto_decrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
{
    if (!c_ctx) {
        memmove(out, in, *dlen);
        return 0;
    }

    const size_t HEADER_SIZE = 20;  // MINIVTUN_MSG_BASIC_HLEN

    if (*dlen < HEADER_SIZE) {
        memmove(out, in, *dlen);
        return 0;
    }

    // 复制header（从未加密）
    memcpy(out, in, HEADER_SIZE);

    // 只解密payload部分
    size_t payload_len = *dlen - HEADER_SIZE;
    if (payload_len == 0) {
        *dlen = HEADER_SIZE;
        return 0;
    }

    void* payload_in = (unsigned char*)in + HEADER_SIZE;
    void* payload_out = (unsigned char*)out + HEADER_SIZE;

    // ... 解密payload_in到payload_out ...

    *dlen = HEADER_SIZE + decrypted_payload_len;
    return 0;
}
```

#### 3. HMAC计算（无需修改）

HMAC计算保持不变，覆盖整个消息：

```c
void crypto_compute_hmac(struct crypto_context* ctx,
                         const void* msg, size_t msg_len,
                         void* tag, size_t tag_len)
{
    // 计算HMAC-SHA256，覆盖整个消息（明文header + 加密payload）
    HMAC(EVP_sha256(),
         ctx->hmac_key, CRYPTO_HMAC_KEY_SIZE,
         msg, msg_len,
         hmac_output, &hmac_len);

    memcpy(tag, hmac_output, tag_len);
}
```

### mbedtls构建配置

为支持HMAC和PBKDF2，mbedtls需要以下模块：

```c
// build.sh 生成的 mbedtls_config.h
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_AES_C
#define MBEDTLS_DES_C
#define MBEDTLS_MD5_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_MD_C          // 消息摘要框架
#define MBEDTLS_SHA224_C      // SHA224（SHA256依赖）
#define MBEDTLS_SHA256_C      // SHA256
#define MBEDTLS_PKCS5_C       // PBKDF2
```

**注意：** mbedtls 3.x要求SHA256和SHA224同时启用。

### 链接器配置

静态链接mbedtls时需使用链接器组解决循环依赖：

```makefile
# Makefile.static
LDLIBS := -L$(MBEDTLS_LIB) -Wl,--start-group -lmbedtls -lmbedx509 -lmbedcrypto -Wl,--end-group
```

---

## 测试验证

### 编译

```bash
# 自动化构建（推荐）
./build.sh

# 或手动构建
make -f Makefile.static clean
make -f Makefile.static
```

### 测试步骤

**1. 启动服务器：**
```bash
./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e 1 -t aes-256
```

**2. 启动客户端：**
```bash
./minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -e 1 -t aes-256
```

**3. 验证连接：**
```bash
ping 10.99.0.1  # 客户端ping服务器
ping 10.99.0.2  # 服务器ping客户端
```

### 预期结果

- ✓ HMAC验证成功
- ✓ 解密成功，opcode正确（0x00 = ECHO_REQ）
- ✓ 隧道建立，ping通
- ✓ 数据传输正常

### 调试输出（已移除）

生产版本已移除调试输出。如需调试，使用`crypto_openssl_debug.c`或手动添加fprintf：

```c
fprintf(stderr, "[ENCRYPT] Header: %zu bytes (plaintext), Payload: %zu bytes\n",
        HEADER_SIZE, payload_len);
```

---

## 安全考虑

### 当前方案的安全性

| 特性 | 状态 | 说明 |
|------|------|------|
| Payload加密 | ✓ | AES-256-CBC |
| 消息完整性 | ✓ | HMAC-SHA256 |
| 身份认证 | ✓ | HMAC基于共享密钥 |
| 密钥派生 | ✓ | PBKDF2-SHA256（100,000迭代） |
| 序列号 | ✓ | 防重放（基本） |
| Header保密 | ✗ | 明文（可接受） |

### Header暴露的影响

**暴露信息：**
- `opcode`：消息类型（ECHO_REQ、IPDATA等）
- `seq`：序列号
- `auth_key`：HMAC值（公开信息）

**风险评估：**
- **低风险：** opcode和seq不包含敏感数据
- **可观察流量模式：** 攻击者可统计消息类型分布
- **无法伪造：** 缺少正确HMAC无法通过验证
- **无法解密payload：** 实际数据仍受保护

### 未来改进方向

1. **AES-GCM模式：**
   - Header作为关联数据（authenticated but not encrypted）
   - 更强的安全保证
   - 抗填充攻击
   - 性能更好（硬件加速）

2. **序列号增强：**
   - 添加时间戳防重放
   - 窗口机制接受乱序包

3. **密钥轮换：**
   - 定期重新协商会话密钥
   - 前向保密（Forward Secrecy）

---

## 文件清单

### 已修改文件

| 文件 | 修改内容 | 后端 |
|------|----------|------|
| `src/crypto_openssl.c` | 只加密payload | OpenSSL |
| `src/crypto_openssl_debug.c` | 调试版本 | OpenSSL |
| `src/crypto_mbedtls.c` | 只加密payload | mbedtls |
| `src/client.c` | HMAC计算逻辑 | 通用 |
| `src/server.c` | HMAC验证逻辑 | 通用 |
| `Makefile.static` | mbedtls链接器组 | 构建 |
| `src/Makefile` | 支持mbedtls后端 | 构建 |
| `build.sh` | mbedtls配置模块 | 构建 |

### 相关文档

- [BUILD.md](../build/BUILD.md) - 完整编译指南
- [HMAC完整修复指南.md](HMAC完整修复指南.md) - 修复步骤详解
- [HMAC安全审计报告.md](HMAC安全审计报告.md) - 安全性分析

---

## 总结

### 问题根源

加密整个消息后用HMAC覆盖auth_key字段会破坏密文，导致CBC解密失败。

### 解决方案

只加密payload，header保持明文。HMAC覆盖整个消息（明文header + 加密payload）。

### 实现状态

✓ 已在OpenSSL和mbedtls后端实现
✓ 已通过测试验证
✓ 已部署到生产环境

### 性能影响

- 加密范围缩小20字节（header大小）
- 性能略有提升（减少加密数据量）
- 无安全性降低（Header本不敏感）

---

**最后更新：** 2026-01-22
**作者：** minivtun团队
**状态：** 已实现并验证
