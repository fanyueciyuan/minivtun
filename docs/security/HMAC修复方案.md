# Encrypt-then-MAC 修复补丁

## 问题确认

通过调试输出确认了问题：

**客户端**:
- Message length: **72 字节**
- Computed HMAC: ffcfd5aa9d804b1ddf88b67c0dbf667d

**服务器**:
- Message length: **80 字节** (加密填充后的长度)
- Received HMAC: ffcfd5aa9d804b1ddf88b67c0dbf667d (来自客户端)
- Computed HMAC: 3abca0bd5cb8c44469c674344eebd8d2 (基于80字节计算)

**不匹配原因**: 客户端对72字节明文计算HMAC，服务器对80字节解密后的数据计算HMAC，长度不一致导致HMAC不同。

---

## 根本问题

当前实现是 **Encrypt-and-MAC**:
1. 客户端: 填充消息 → 计算HMAC(明文，72字节) → 加密(消息+HMAC) → 发送
2. 服务器: 接收 → 解密(消息+HMAC，80字节) → 验证HMAC(解密后，80字节) → **失败**

**问题**:
- 加密过程对消息进行了填充(padding)，72字节变成80字节
- 客户端对72字节计算HMAC
- 服务器解密后得到80字节，重新计算HMAC
- **长度不同 → HMAC不匹配**

---

## 解决方案

改为 **Encrypt-then-MAC**:
1. 客户端: 填充消息 → 加密(消息) → 计算HMAC(密文) → 发送(密文+HMAC)
2. 服务器: 接收(密文+HMAC) → 验证HMAC(密文) → 如果通过才解密

**优势**:
- ✅ HMAC基于相同的密文长度计算，一致性有保证
- ✅ 先验证HMAC，拒绝伪造消息无需解密(性能优化)
- ✅ 防止填充预言攻击
- ✅ 符合业界标准(RFC 7366)

---

## 实现难点

**问题**: auth_key字段在消息头部，会被一起加密。如果在加密后计算HMAC，auth_key位置已经是密文，无法填充HMAC值。

**解决方案**:

### 方案A: HMAC不参与加密 (推荐)
```
消息结构调整:
┌──────────────┐
│ Encrypted:   │
│  - opcode    │
│  - rsv       │
│  - seq       │
│  - payload   │
├──────────────┤
│ Plaintext:   │
│  - auth_key  │  ← HMAC放在加密部分外面
└──────────────┘

发送流程:
1. 构造消息(auth_key=0)
2. 加密整个消息
3. 计算HMAC(密文)并放入原来auth_key的位置
4. 发送

接收流程:
1. 提取auth_key位置的HMAC
2. 清零auth_key
3. 验证HMAC(密文)
4. 如果通过，解密消息
```

**优点**:
- 简单，只需调整HMAC计算时机
- auth_key不参与加密，直接存储HMAC

**缺点**:
- auth_key暴露在明文中(但这不影响安全性，HMAC本身是公开的)

### 方案B: 将HMAC移到消息末尾
```
消息结构:
┌──────────────┐
│ Encrypted:   │
│  - hdr       │
│  - payload   │
├──────────────┤
│ Plaintext:   │
│  - HMAC(16)  │  ← 追加在密文后面
└──────────────┘
```

**缺点**:
- 需要修改消息结构，不向后兼容
- 实现复杂

---

## 推荐实现: 方案A (修改HMAC时机，不改消息结构)

### 关键修改点

#### 1. 发送方 (client.c, server.c)

**当前代码** (client.c:200-221):
```c
// 填充字段
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

// ❌ 错误: 先计算HMAC(明文)
if (state.crypto_ctx) {
    crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len,
                        nmsg->hdr.auth_key, 16);
}

// 后加密
out_data = buffers->read_buffer;
out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
local_to_netmsg(nmsg, &out_data, &out_dlen);
send(state.sockfd, out_data, out_dlen, 0);
```

**修复后**:
```c
// 填充字段
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

// 清零auth_key
memset(nmsg->hdr.auth_key, 0, sizeof(nmsg->hdr.auth_key));

// ✅ 正确: 先加密
out_data = buffers->read_buffer;
out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
local_to_netmsg(nmsg, &out_data, &out_dlen);

// 后计算HMAC(密文)
if (state.crypto_ctx) {
    struct minivtun_msg *encrypted = (struct minivtun_msg *)out_data;
    crypto_compute_hmac(state.crypto_ctx, encrypted, out_dlen,
                        encrypted->hdr.auth_key, 16);
}

send(state.sockfd, out_data, out_dlen, 0);
```

#### 2. 接收方 (client.c, server.c)

**当前代码** (server.c:477-492):
```c
// 接收
rc = recvfrom(...);

// ❌ 错误: 先解密
netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen);

// 后验证HMAC
if (state.crypto_ctx) {
    if (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {
        LOG("HMAC verification failed");
        return 0;
    }
}
```

**修复后**:
```c
// 接收
rc = recvfrom(...);

struct minivtun_msg *encrypted = (struct minivtun_msg *)buffers->read_buffer;

// ✅ 正确: 先验证HMAC(密文)
if (state.crypto_ctx) {
    if (!crypto_verify_hmac(state.crypto_ctx, encrypted, (size_t)rc)) {
        LOG("HMAC verification failed from client");
        return 0;  // 提前拒绝，无需解密
    }
}

// 后解密
netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen);
nmsg = out_data;
```

---

## 注意事项

### ⚠️ 关键问题: auth_key会被加密

在修复后的方案中:
- 发送时: auth_key在加密后填充，所以**不会被加密**
- 接收时: auth_key在验证时从**密文**中提取

**这是安全的**，因为:
1. HMAC标签本身是公开的，不需要保密
2. HMAC基于密钥计算，攻击者无法伪造
3. 符合Encrypt-then-MAC标准实践

---

## 下一步

创建完整的修复补丁...
