# 🔍 HMAC 加密实现安全审计报告

**审计日期**: 2026-01-20
**代码版本**: cb95d59 (最新修复)
**审计范围**: HMAC-SHA256 认证机制完整性检查

---

## ✅ 审计结论

**总体评价**: **发现 1 个严重安全漏洞**

- ✅ HMAC 算法实现正确 (SHA-256)
- ✅ 密钥派生安全 (PBKDF2-SHA256, 100,000 次迭代)
- ✅ 时序攻击防护正确 (常量时间比较)
- ✅ 字段填充顺序正确 (先填充再计算 HMAC)
- ✅ 条件判断正确 (有/无加密模式)
- ❌ **发现严重漏洞**: HMAC 在加密**之前**计算，在解密**之后**验证 (Encrypt-then-MAC 顺序错误)

---

## 🚨 严重安全漏洞详解

### 漏洞 1: HMAC 执行顺序错误 (Encrypt-and-MAC 而非 Encrypt-then-MAC)

#### 问题描述

**当前实现**:
1. **发送方** (client.c:200-221, server.c:643-661):
   ```
   填充消息字段 → 计算 HMAC (明文) → 加密整个消息
   ```

2. **接收方** (client.c:94-109, server.c:477-492):
   ```
   解密整个消息 → 验证 HMAC (明文)
   ```

**正确实现** (Encrypt-then-MAC):
1. **发送方**:
   ```
   填充消息字段 → 加密消息 → 计算 HMAC (密文)
   ```

2. **接收方**:
   ```
   验证 HMAC (密文) → 解密消息
   ```

#### 代码证据

**client.c: tunnel_receiving() - 发送方 (Lines 200-221)**
```c
/* 1. 填充字段 */
nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
nmsg->hdr.seq = htons(state.xmit_seq++);
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

/* 2. 计算 HMAC (在加密之前！) */
if (state.crypto_ctx) {
    size_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
    crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,  // ← 明文 HMAC
                        nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
}

/* 3. 加密消息 (HMAC 已经在 hdr.auth_key 中) */
out_data = buffers->read_buffer;
out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {  // ← 加密包含 HMAC 的整个消息
    LOG("Encryption failed");
    return 0;
}

/* 4. 发送 */
(void)send(state.sockfd, out_data, out_dlen, 0);
```

**client.c: network_receiving() - 接收方 (Lines 87-109)**
```c
/* 1. 接收加密消息 */
rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0, ...);

/* 2. 解密消息 */
out_data = buffers->crypt_buffer;
out_dlen = (size_t)rc;
if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {  // ← 先解密
    LOG("Decryption failed.");
    return 0;
}
nmsg = out_data;

/* 3. 验证 HMAC (解密后的明文) */
if (state.crypto_ctx) {
    if (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {  // ← 验证明文 HMAC
        LOG("HMAC verification failed - message authentication error");
        return 0;
    }
}
```

#### 安全影响

**当前实现 (Encrypt-and-MAC)**:
- ❌ **填充预言攻击 (Padding Oracle Attack)**: 攻击者可以通过观察解密失败/HMAC 失败来推断明文
- ❌ **时序侧信道攻击**: 解密时间差异可能泄露信息
- ❌ **HMAC 被加密**: HMAC 标签本身被加密，无法在解密前验证完整性
- ❌ **解密无效数据**: 接收方必须先解密（计算密集型）才能验证消息是否有效

**正确实现 (Encrypt-then-MAC)**:
- ✅ 先验证 HMAC，拒绝被篡改的消息（无需解密）
- ✅ 防止填充预言攻击
- ✅ 防止时序侧信道攻击
- ✅ 性能优化：恶意消息无需解密即可拒绝

#### 攻击场景示例

**攻击者可以执行以下操作**:

1. **填充预言攻击**:
   ```
   攻击者截获密文 C
   攻击者修改最后一个加密块的最后一个字节
   发送修改后的密文 C' 到服务器

   服务器响应:
   - "Decryption failed" → 填充无效 → 泄露信息
   - "HMAC verification failed" → 填充有效但 HMAC 错误 → 泄露信息

   重复多次后，攻击者可以恢复明文
   ```

2. **DoS 攻击**:
   ```
   攻击者发送大量伪造密文
   服务器必须对每个消息执行解密（计算密集型）
   即使 HMAC 验证会失败，但已经浪费了 CPU 资源

   如果使用 Encrypt-then-MAC:
   服务器只需验证 HMAC（轻量级），立即拒绝伪造消息，无需解密
   ```

#### 漏洞评级

- **严重性**: 🔴 **高危 (High)**
- **可利用性**: 🟡 **中等** (需要中间人位置，但技术上可行)
- **影响范围**: 🔴 **机密性 + 完整性**
- **CVE 等级**: 预计 **7.5-8.5 (High)**

---

## ✅ 其他安全检查通过项

### 1. HMAC 算法实现 ✅

**检查项**: HMAC-SHA256 实现是否正确

**代码**: `crypto_openssl.c:226-243`
```c
void crypto_compute_hmac(struct crypto_context* ctx,
                         const void* msg, size_t msg_len,
                         void* tag, size_t tag_len)
{
    if (!ctx || !msg || !tag) return;

    unsigned char hmac_output[32]; /* SHA-256 output */
    unsigned int hmac_len;

    HMAC(EVP_sha256(),                      // ✅ 使用 SHA-256
         ctx->hmac_key, CRYPTO_HMAC_KEY_SIZE,  // ✅ 32 字节密钥
         msg, msg_len,
         hmac_output, &hmac_len);

    /* Copy first tag_len bytes */
    size_t copy_len = (tag_len < hmac_len) ? tag_len : hmac_len;
    memcpy(tag, hmac_output, copy_len);     // ✅ 截断到 16 字节
}
```

**结论**: ✅ **安全**
- 使用业界标准 HMAC-SHA256
- OpenSSL 库实现可信
- 输出截断到 16 字节（128 位）安全性足够

---

### 2. 密钥派生 (KDF) ✅

**检查项**: 从密码派生密钥是否安全

**代码**: `crypto_openssl.c:99-127`
```c
/* Use PBKDF2 to derive key material */
const unsigned char salt[] = "minivtun-v2-salt-2026";  // ✅ 固定盐
const int iterations = 100000;                          // ✅ 10万次迭代
unsigned char key_material[64];  /* 32 bytes encryption + 32 bytes HMAC */

int ret = PKCS5_PBKDF2_HMAC(
    password, strlen(password),
    salt, sizeof(salt) - 1,
    iterations,                     // ✅ 100,000 次迭代
    EVP_sha256(),                   // ✅ SHA-256
    sizeof(key_material),
    key_material
);

/* Split key material: first part for encryption, second for HMAC */
memcpy(ctx->enc_key, key_material, ctx->enc_key_len);  // ✅ 前 16/32 字节 → 加密密钥
memcpy(ctx->hmac_key, key_material + 32, CRYPTO_HMAC_KEY_SIZE);  // ✅ 后 32 字节 → HMAC 密钥

/* Clear sensitive data */
memset(key_material, 0, sizeof(key_material));  // ✅ 清除内存
```

**结论**: ✅ **安全**
- PBKDF2-HMAC-SHA256 是业界标准
- 100,000 次迭代符合 NIST 推荐（≥ 10,000）
- 密钥分离正确（加密密钥 ≠ HMAC 密钥）
- 敏感数据清除正确

**⚠️ 轻微问题** (非安全漏洞):
- 固定盐 `"minivtun-v2-salt-2026"` 对所有用户相同
- 影响: 如果两个用户使用相同密码，派生的密钥相同
- 建议: 使用随机盐（需要协议修改）
- 实际风险: **低** (假设用户使用不同密码)

---

### 3. 时序攻击防护 ✅

**检查项**: HMAC 比较是否使用常量时间算法

**代码**: `crypto_openssl.c:267-273`
```c
/* 5. Constant-time comparison (prevent timing attack) */
int result = 0;
for (size_t i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
    result |= (received_tag[i] ^ computed_tag[i]);  // ✅ 位运算，每次迭代时间相同
}

return (result == 0);  // ✅ 只在最后判断
```

**结论**: ✅ **安全**
- 使用位异或运算（XOR）确保每次迭代时间相同
- 不使用 `memcmp()` (可能提前返回)
- 不使用短路逻辑（`&&` 或 `||`）
- 完整遍历所有 16 字节

---

### 4. 字段填充顺序 ✅

**检查项**: HMAC 是否在消息字段填充**之后**计算

**代码**: `client.c:200-212`
```c
memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
nmsg->hdr.seq = htons(state.xmit_seq++);

/* Fill ipdata fields BEFORE computing HMAC */  // ✅ 先填充
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

/* Compute HMAC (only if encryption is enabled) */  // ✅ 后计算
if (state.crypto_ctx) {
    size_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
    crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
                        nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
}
```

**结论**: ✅ **正确** (已在 commit 54961e4 修复)

---

### 5. 条件判断 ✅

**检查项**: HMAC 是否只在启用加密时执行

**代码**: `client.c:104, 208, 247` 和 `server.c:346, 487, 650`
```c
if (state.crypto_ctx) {  // ✅ 检查是否为 NULL
    crypto_compute_hmac(...);
}

if (state.crypto_ctx) {  // ✅ 检查是否为 NULL
    if (!crypto_verify_hmac(...)) {
        LOG("HMAC verification failed");
        return 0;
    }
}
```

**结论**: ✅ **正确** (已在 commit cb95d59 修复)

---

### 6. HMAC 验证实现 ✅

**检查项**: `crypto_verify_hmac()` 是否正确提取和恢复 auth_key

**代码**: `crypto_openssl.c:245-274`
```c
bool crypto_verify_hmac(struct crypto_context* ctx, void* msg, size_t msg_len)
{
    if (!ctx || !msg) return false;

    unsigned char *msg_bytes = (unsigned char*)msg;
    unsigned char received_tag[CRYPTO_AUTH_TAG_SIZE];
    unsigned char computed_tag[CRYPTO_AUTH_TAG_SIZE];

    /* 1. Extract received HMAC (offset 4 = sizeof(opcode+rsv+seq)) */
    memcpy(received_tag, msg_bytes + 4, CRYPTO_AUTH_TAG_SIZE);  // ✅ 提取

    /* 2. Clear auth_key field to zero */
    memset(msg_bytes + 4, 0, CRYPTO_AUTH_TAG_SIZE);  // ✅ 清零

    /* 3. Compute HMAC */
    crypto_compute_hmac(ctx, msg, msg_len, computed_tag, CRYPTO_AUTH_TAG_SIZE);

    /* 4. Restore original auth_key (for subsequent processing) */
    memcpy(msg_bytes + 4, received_tag, CRYPTO_AUTH_TAG_SIZE);  // ✅ 恢复

    /* 5. Constant-time comparison */
    int result = 0;
    for (size_t i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        result |= (received_tag[i] ^ computed_tag[i]);
    }

    return (result == 0);
}
```

**结论**: ✅ **正确**
- 正确提取 `hdr.auth_key` (偏移 4 字节)
- 计算 HMAC 前清零该字段（确保发送方和接收方计算输入相同）
- 验证后恢复原值（避免影响后续处理）

---

### 7. 消息结构和偏移 ✅

**检查项**: HMAC 计算的消息长度是否正确

**代码**: `minivtun.h:131-161`
```c
struct minivtun_msg {
    struct {
        __u8 opcode;        // 偏移 0
        __u8 rsv;           // 偏移 1
        __be16 seq;         // 偏移 2
        __u8 auth_key[16];  // 偏移 4 ✅
    } __attribute__((packed)) hdr; /* 20 */

    union {
        struct {
            __be16 proto;   /* ETH_P_IP or ETH_P_IPV6 */
            __be16 ip_dlen; /* Total length of IP/IPv6 data */
            char data[];    // Flexible array member
        } __attribute__((packed)) ipdata;
        struct {
            ...
            __be32 id;
        } __attribute__((packed)) echo; /* 24 */
    };
} __attribute__((packed));

#define MINIVTUN_MSG_BASIC_HLEN  (sizeof(((struct minivtun_msg *)0)->hdr))  // = 20
#define MINIVTUN_MSG_IPDATA_OFFSET  (offsetof(struct minivtun_msg, ipdata.data))  // = 24
```

**HMAC 计算范围**:
- **IPDATA 消息**: `MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen` = 24 + 数据长度 ✅
- **ECHO 消息**: `MINIVTUN_MSG_BASIC_HLEN + sizeof(echo)` = 20 + 24 = 44 ✅

**结论**: ✅ **正确**

---

## 🔧 漏洞修复建议

### 修复方案: 实现 Encrypt-then-MAC

#### 修改 1: 发送方 - 先加密，后计算 HMAC

**client.c: tunnel_receiving() (Lines 200-221)**

**当前代码**:
```c
/* 1. 填充字段 */
nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
nmsg->hdr.seq = htons(state.xmit_seq++);
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

/* 2. 计算 HMAC (明文) */
if (state.crypto_ctx) {
    crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
                        nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
}

/* 3. 加密 */
out_data = buffers->read_buffer;
out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
    return 0;
}

/* 4. 发送 */
(void)send(state.sockfd, out_data, out_dlen, 0);
```

**修复后**:
```c
/* 1. 填充字段 */
nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
nmsg->hdr.seq = htons(state.xmit_seq++);
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

/* 2. 清零 auth_key (加密前) */
memset(nmsg->hdr.auth_key, 0, sizeof(nmsg->hdr.auth_key));

/* 3. 加密消息 (不含 HMAC) */
out_data = buffers->read_buffer;
out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
    return 0;
}

/* 4. 计算 HMAC (对加密后的数据) */
if (state.crypto_ctx) {
    struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)out_data;
    crypto_compute_hmac(state.crypto_ctx, encrypted_msg, out_dlen,
                        encrypted_msg->hdr.auth_key, sizeof(encrypted_msg->hdr.auth_key));
}

/* 5. 发送 */
(void)send(state.sockfd, out_data, out_dlen, 0);
```

#### 修改 2: 接收方 - 先验证 HMAC，后解密

**client.c: network_receiving() (Lines 87-109)**

**当前代码**:
```c
/* 1. 接收 */
rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0, ...);

/* 2. 解密 */
out_data = buffers->crypt_buffer;
out_dlen = (size_t)rc;
if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
    return 0;
}
nmsg = out_data;

/* 3. 验证 HMAC */
if (state.crypto_ctx) {
    if (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {
        return 0;
    }
}
```

**修复后**:
```c
/* 1. 接收 */
rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0, ...);

struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)buffers->read_buffer;
size_t encrypted_len = (size_t)rc;

/* 2. 验证 HMAC (对密文) */
if (state.crypto_ctx) {
    if (!crypto_verify_hmac(state.crypto_ctx, encrypted_msg, encrypted_len)) {
        LOG("HMAC verification failed - message authentication error");
        return 0;  // ← 提前拒绝，无需解密
    }
}

/* 3. 解密 */
out_data = buffers->crypt_buffer;
out_dlen = encrypted_len;
if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
    LOG("Decryption failed.");
    return 0;
}
nmsg = out_data;
```

#### 修改 3: 更新 crypto_verify_hmac() 函数

**crypto_openssl.c: crypto_verify_hmac()**

**问题**: 当前实现假设 `auth_key` 在解密后是明文
**修复**: 需要处理加密后的 `auth_key`

**修复后的函数**:
```c
bool crypto_verify_hmac(struct crypto_context* ctx, void* msg, size_t msg_len)
{
    if (!ctx || !msg) return false;

    unsigned char *msg_bytes = (unsigned char*)msg;
    unsigned char received_tag[CRYPTO_AUTH_TAG_SIZE];
    unsigned char computed_tag[CRYPTO_AUTH_TAG_SIZE];

    /* 1. Extract received HMAC (offset 4) */
    memcpy(received_tag, msg_bytes + 4, CRYPTO_AUTH_TAG_SIZE);

    /* 2. Clear auth_key field to zero */
    memset(msg_bytes + 4, 0, CRYPTO_AUTH_TAG_SIZE);

    /* 3. Compute HMAC on the entire message with auth_key cleared */
    crypto_compute_hmac(ctx, msg, msg_len, computed_tag, CRYPTO_AUTH_TAG_SIZE);

    /* 4. Restore original auth_key */
    memcpy(msg_bytes + 4, received_tag, CRYPTO_AUTH_TAG_SIZE);

    /* 5. Constant-time comparison */
    int result = 0;
    for (size_t i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        result |= (received_tag[i] ^ computed_tag[i]);
    }

    return (result == 0);
}
```

**注意**: 如果 HMAC 在密文上计算，`crypto_verify_hmac()` 需要知道消息是否已加密。可能需要添加参数或修改逻辑。

---

## 📊 修复优先级

| 问题 | 严重性 | 优先级 | 影响 |
|------|--------|--------|------|
| Encrypt-and-MAC → Encrypt-then-MAC | 🔴 高危 | P0 | 机密性、完整性、DoS |

---

## 🧪 修复后测试建议

### 测试 1: 中间人篡改测试
```bash
# 使用 tcpdump 捕获数据包
sudo tcpdump -i any -w capture.pcap udp port 9999

# 使用 scapy 修改数据包并重放
# 预期: HMAC 验证失败，服务器拒绝消息
```

### 测试 2: 性能测试
```bash
# 发送大量伪造数据包
# 修复前: 服务器 CPU 使用率高（需要解密）
# 修复后: 服务器 CPU 使用率低（HMAC 验证失败后直接拒绝）
```

### 测试 3: 填充预言攻击测试
```bash
# 使用 Padding Oracle 攻击工具
# 修复前: 可能恢复部分明文
# 修复后: 攻击失败（先验证 HMAC）
```

---

## 📚 参考资料

- **Encrypt-then-MAC**: [Krawczyk 2001] "The Order of Encryption and Authentication for Protecting Communications"
- **NIST SP 800-38D**: Authenticated Encryption Modes (GCM)
- **RFC 7366**: Encrypt-then-MAC for TLS and DTLS
- **OWASP**: Cryptographic Storage Cheat Sheet

---

## 📝 修复检查清单

修复完成后，请确认:

- [ ] 所有发送路径: HMAC 在加密**之后**计算
- [ ] 所有接收路径: HMAC 在解密**之前**验证
- [ ] 无加密模式: 跳过 HMAC 和加密（当前已正确）
- [ ] 加密模式: 严格按 Encrypt-then-MAC 顺序
- [ ] `crypto_verify_hmac()`: 正确处理加密消息
- [ ] 所有消息类型: IPDATA, ECHO_REQ, ECHO_ACK 都已修复
- [ ] 客户端和服务器: 双向修复一致
- [ ] 单元测试: 添加 Encrypt-then-MAC 测试用例
- [ ] 性能测试: 验证伪造消息不触发解密
- [ ] 安全测试: 填充预言攻击失败

---

**报告作者**: Claude Code (Anthropic)
**审计工具**: 静态代码分析 + 手工审计
**下一步**: 建议立即修复该漏洞并重新测试
