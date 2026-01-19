# MiniVTun HMAC Authentication Fix - Apply Script

## 修改文件清单

已完成:
- ✅ src/crypto_wrapper.h
- ✅ src/crypto_openssl.c

需要手动修改:
- ⏳ src/client.c (3处修改)
- ⏳ src/server.c (3处修改)
- ⏳ src/crypto_mbedtls.c (可选,如果使用 mbedTLS)

---

## client.c 修改说明

### 修改 1: network_receiving() - 第 103-104 行

**查找:**
```c
if (memcmp(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key)) != 0)
    return 0;
```

**替换为:**
```c
/* Verify HMAC authentication */
if (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {
    LOG("HMAC verification failed - message authentication error");
    return 0;
}
```

---

### 修改 2: tunnel_receiving() - 第 198 行

**查找:**
```c
memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
```

**替换为:**
```c
/* Compute HMAC (auth_key field is currently zero) */
size_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
```

---

### 修改 3: do_an_echo_request() - 第 226 行

**查找:**
```c
memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
```

**替换为:**
```c
/* Compute HMAC for ECHO request */
size_t msg_len_for_hmac = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
```

---

## server.c 修改说明

### 修改 1: reply_an_echo_ack() - 第 343 行

**查找:**
```c
memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
```

**替换为:**
```c
/* Compute HMAC for ECHO response */
size_t msg_len_for_hmac = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
```

---

### 修改 2: network_receiving() - 第 480 行

**查找:**
```c
if (memcmp(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key)) != 0)
    return 0;
```

**替换为:**
```c
/* Verify HMAC authentication */
if (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {
    LOG("HMAC verification failed from client");
    return 0;
}
```

---

### 修改 3: tunnel_receiving() - 第 634 行

**查找:**
```c
memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
```

**替换为:**
```c
/* Compute HMAC (auth_key field is currently zero) */
size_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
```

---

## 编译测试

```bash
cd src
make clean
make

# 如果出现编译错误,检查:
# 1. OpenSSL 版本 >= 1.0.0
# 2. 是否正确包含 <stdbool.h>
# 3. PBKDF2 函数是否可用
```

---

## 功能测试

### 测试 1: 基本连通性

```bash
# 服务器
./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e "test_password" -n mv0

# 客户端
./minivtun -r 127.0.0.1:9999 -a 10.99.0.2/24 -e "test_password" -n mv1

# 测试
ping -c 3 10.99.0.1
```

### 测试 2: 错误密码拒绝

```bash
# 使用错误密码的客户端
./minivtun -r 127.0.0.1:9999 -a 10.99.0.3/24 -e "wrong_password" -n mv2

# 预期: 无法通信,日志显示 "HMAC verification failed"
```

### 测试 3: 性能测试

```bash
# 服务器端
iperf3 -s

# 客户端通过隧道测试
iperf3 -c 10.99.0.1 -t 30

# 预期: 吞吐量约为原版的 95-98%
```

---

## 验证清单

- [ ] 代码编译无错误无警告
- [ ] 客户端和服务器能正常建立连接
- [ ] 错误密码被正确拒绝
- [ ] 数据传输正常 (ping, iperf)
- [ ] 日志中无 "HMAC verification failed" 误报
- [ ] 性能无显著下降 (吞吐量 > 90%)

---

## 故障排除

### 问题 1: 编译错误 "undefined reference to `PKCS5_PBKDF2_HMAC`"

**原因**: OpenSSL 版本过旧

**解决**:
```bash
# 检查 OpenSSL 版本
openssl version

# 升级 OpenSSL (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install libssl-dev

# 或使用 mbedTLS 后端
make CRYPTO_BACKEND=mbedtls
```

### 问题 2: 运行时 "HMAC verification failed"

**可能原因**:
1. 客户端和服务器密码不一致
2. 时钟同步问题 (如果未来增加时间戳验证)
3. 网络数据包损坏

**调试**:
```bash
# 启用详细日志
# 在代码中临时添加:
LOG("HMAC debug - msg_len=%zu, tag=%02x%02x%02x%02x...",
    msg_len, tag[0], tag[1], tag[2], tag[3]);
```

### 问题 3: 初始化缓慢

**原因**: PBKDF2 100000 次迭代

**优化** (不推荐,会降低安全性):
```c
// crypto_openssl.c line 101
const int iterations = 10000; // 降低到 10000 次
```

---

## 回退方案

如果修复后出现问题,可恢复原版本:

```bash
cd src
git checkout crypto_wrapper.h crypto_openssl.c client.c server.c
make clean && make
```

---

## 下一步优化 (可选)

1. **修复固定 IV**: 参考方案 3 使用随机 IV
2. **增加重放防护**: 实现序列号验证
3. **密钥轮换**: 定期更换密码
4. **迁移到 AEAD**: 使用 AES-GCM 替换 CBC+HMAC

---

**修复完成后预期效果**:

✅ 修复认证失效 bug,程序能正常工作
✅ 使用强密钥派生 (PBKDF2 10万次迭代)
✅ HMAC-SHA256 消息认证,防止数据篡改
✅ 时序安全的比较,防御 timing attack
✅ 密钥材料正确清理,防止内存泄漏

**安全强度**: 从 无效 → 中高 (适合生产环境基础安全需求)
