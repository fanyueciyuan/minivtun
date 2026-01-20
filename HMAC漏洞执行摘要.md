# 🚨 HMAC 加密漏洞 - 执行摘要

**发现日期**: 2026-01-20
**严重性**: 🔴 **高危 (High)**
**状态**: ❌ **未修复**

---

## 漏洞概述

MiniVTun 的 HMAC-SHA256 认证实现存在**架构级安全漏洞**：

**当前实现**: Encrypt-and-MAC (错误)
```
发送: 填充消息 → 计算 HMAC(明文) → 加密(消息+HMAC)
接收: 解密(消息+HMAC) → 验证 HMAC(明文)
```

**正确实现**: Encrypt-then-MAC (安全)
```
发送: 填充消息 → 加密(消息) → 计算 HMAC(密文)
接收: 验证 HMAC(密文) → 如果通过才解密(消息)
```

---

## 为什么当前实现不安全？

### 问题 1: 填充预言攻击 (Padding Oracle Attack)

**攻击流程**:
1. 攻击者截获加密消息
2. 修改密文的某些字节
3. 发送给服务器
4. 观察服务器响应:
   - "Decryption failed" → 填充错误 → 泄露信息
   - "HMAC verification failed" → 填充正确但内容被篡改 → 泄露信息
5. 重复多次后，攻击者可以**逐字节恢复明文**

**如果使用 Encrypt-then-MAC**:
- 服务器先验证 HMAC
- 如果 HMAC 失败，**直接拒绝，不解密**
- 攻击者无法获得"Decryption failed"的信息
- 攻击失败！

### 问题 2: 必须解密才能验证完整性

**当前流程**:
```
恶意消息 → 服务器解密(消耗 CPU) → HMAC 验证失败 → 丢弃
```

**影响**:
- 攻击者可以发送大量伪造消息
- 服务器必须对每个消息执行解密（计算密集型）
- **DoS 攻击风险**

**如果使用 Encrypt-then-MAC**:
```
恶意消息 → 服务器验证 HMAC(轻量级) → 失败 → 直接拒绝，无需解密
```

### 问题 3: 时序侧信道攻击

虽然当前实现的 HMAC 比较使用了常量时间算法（✅ 正确），但解密过程可能泄露信息：

- 解密失败的时间 ≠ HMAC 验证失败的时间
- 攻击者可以通过测量响应时间来区分失败原因
- 可能泄露部分明文信息

---

## 受影响的代码位置

### 发送方 (6 处)
1. **client.c:208-212** - tunnel_receiving() - IPDATA 消息
2. **client.c:247-251** - do_an_echo_request() - ECHO_REQ 消息
3. **server.c:646-654** - tunnel_receiving() - IPDATA 消息
4. **server.c:346-350** - reply_an_echo_ack() - ECHO_ACK 消息

### 接收方 (2 处)
5. **client.c:94-109** - network_receiving() - 解密后验证
6. **server.c:477-492** - network_receiving() - 解密后验证

---

## 漏洞评级

| 项目 | 评分 |
|------|------|
| **严重性** | 🔴 高危 (High) |
| **可利用性** | 🟡 中等 (需要中间人位置) |
| **影响** | 🔴 机密性 + 完整性 + 可用性 |
| **CVE 等级** | 预计 7.5-8.5 |

---

## 修复方案概述

### 关键修改点

#### 修改 1: 发送方 - 移动 HMAC 计算到加密之后

**当前** (client.c:200-221):
```c
/* 填充字段 */
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

/* ❌ 错误: 先计算 HMAC (明文) */
crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len, ...);

/* 再加密 */
local_to_netmsg(nmsg, &out_data, &out_dlen);
send(state.sockfd, out_data, out_dlen, 0);
```

**修复后**:
```c
/* 填充字段 */
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
memset(nmsg->hdr.auth_key, 0, sizeof(nmsg->hdr.auth_key));  // ← 清零

/* 先加密 */
local_to_netmsg(nmsg, &out_data, &out_dlen);

/* ✅ 正确: 后计算 HMAC (密文) */
struct minivtun_msg *encrypted = (struct minivtun_msg *)out_data;
crypto_compute_hmac(state.crypto_ctx, encrypted, out_dlen,
                    encrypted->hdr.auth_key, sizeof(encrypted->hdr.auth_key));

send(state.sockfd, out_data, out_dlen, 0);
```

#### 修改 2: 接收方 - 移动 HMAC 验证到解密之前

**当前** (client.c:87-109):
```c
/* 接收 */
rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0, ...);

/* ❌ 错误: 先解密 */
netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen);

/* 后验证 HMAC */
crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen);
```

**修复后**:
```c
/* 接收 */
rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0, ...);

struct minivtun_msg *encrypted = (struct minivtun_msg *)buffers->read_buffer;

/* ✅ 正确: 先验证 HMAC (密文) */
if (!crypto_verify_hmac(state.crypto_ctx, encrypted, (size_t)rc)) {
    return 0;  // ← 提前拒绝，不浪费 CPU 解密
}

/* 后解密 */
netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen);
```

---

## 需要修改的文件

1. **src/client.c** - 3 处修改
2. **src/server.c** - 3 处修改
3. **src/crypto_openssl.c** - 可能需要调整 `crypto_verify_hmac()` 逻辑
4. **src/crypto_mbedtls.c** - 同步修改 (如果使用 mbedTLS)

---

## 测试建议

### 测试 1: 功能测试
```bash
# 修复后，正常通信应该仍然工作
sudo ./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e "password" -n mv0
# 客户端
sudo ./minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -e "password" -n mv1
ping -c 5 10.99.0.1  # 应该 0% packet loss
```

### 测试 2: 安全测试
```bash
# 捕获数据包
sudo tcpdump -i any -w packets.pcap udp port 9999

# 使用 scapy 修改密文字节并重放
# 预期:
# - 修复前: 服务器解密失败或 HMAC 失败 (泄露信息)
# - 修复后: 服务器 HMAC 失败 (不解密，无信息泄露)
```

### 测试 3: 性能测试
```bash
# 使用工具发送 10000 个伪造数据包
# 测量服务器 CPU 使用率

# 预期:
# - 修复前: CPU 高 (需要解密所有伪造消息)
# - 修复后: CPU 低 (只验证 HMAC，不解密)
```

---

## 修复时间表建议

- **P0 (立即)**: 修复 Encrypt-and-MAC → Encrypt-then-MAC
- **预计工作量**: 4-6 小时 (代码修改 + 测试)
- **风险**: 中 (需要改变加密/HMAC 顺序，需要仔细测试)

---

## ✅ 已经正确的部分

以下部分**不需要修改**:

- ✅ HMAC-SHA256 算法实现
- ✅ PBKDF2 密钥派生 (100,000 次迭代)
- ✅ 常量时间 HMAC 比较 (防时序攻击)
- ✅ 字段填充顺序 (先填充再计算 HMAC)
- ✅ 条件判断 (有/无加密模式)
- ✅ 密钥分离 (加密密钥 ≠ HMAC 密钥)

**唯一问题**: HMAC 计算/验证的**时机**不对（应该在加密之后/解密之前）

---

## 结论

MiniVTun 的 HMAC 实现**基础是正确的**（算法、密钥派生、时序攻击防护都没问题），但**架构设计有严重缺陷**：

- 当前使用 **Encrypt-and-MAC**（不安全）
- 应该改为 **Encrypt-then-MAC**（业界标准）

**风险**:
- 填充预言攻击可能恢复明文
- DoS 攻击可能耗尽服务器 CPU
- 时序侧信道可能泄露信息

**建议**: 立即修复此漏洞，修改相对简单（调整 HMAC 计算/验证时机），但需要仔细测试。

---

**详细分析**: 请查看 `HMAC安全审计报告.md`
