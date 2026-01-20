# 🐛 HMAC 验证失败 - Debug 测试指南

## 问题症状

- ✅ 无加密模式正常工作
- ❌ 加密模式: "HMAC verification failed from client"
- 服务器命令: `./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e 1 -t aes-128`
- 客户端命令: `./minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -e 1 -t aes-128`

---

## 🔍 调试方法 1: 添加详细日志 (推荐)

### 步骤 1: 修改 crypto_openssl.c 添加调试输出

编辑 `src/crypto_openssl.c`，在 `crypto_verify_hmac()` 函数中添加调试信息：

```c
bool crypto_verify_hmac(struct crypto_context* ctx, void* msg, size_t msg_len)
{
    if (!ctx || !msg) return false;

    unsigned char *msg_bytes = (unsigned char*)msg;
    unsigned char received_tag[CRYPTO_AUTH_TAG_SIZE];
    unsigned char computed_tag[CRYPTO_AUTH_TAG_SIZE];

    /* 1. Extract received HMAC */
    memcpy(received_tag, msg_bytes + 4, CRYPTO_AUTH_TAG_SIZE);

    /* DEBUG: 打印接收到的 HMAC */
    fprintf(stderr, "DEBUG: Received HMAC: ");
    for (int i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        fprintf(stderr, "%02x", received_tag[i]);
    }
    fprintf(stderr, "\n");

    /* 2. Clear auth_key field to zero */
    memset(msg_bytes + 4, 0, CRYPTO_AUTH_TAG_SIZE);

    /* 3. Compute HMAC */
    crypto_compute_hmac(ctx, msg, msg_len, computed_tag, CRYPTO_AUTH_TAG_SIZE);

    /* DEBUG: 打印计算的 HMAC */
    fprintf(stderr, "DEBUG: Computed HMAC: ");
    for (int i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        fprintf(stderr, "%02x", computed_tag[i]);
    }
    fprintf(stderr, "\n");

    /* DEBUG: 打印消息长度 */
    fprintf(stderr, "DEBUG: Message length: %zu\n", msg_len);

    /* 4. Restore original auth_key */
    memcpy(msg_bytes + 4, received_tag, CRYPTO_AUTH_TAG_SIZE);

    /* 5. Constant-time comparison */
    int result = 0;
    for (size_t i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        result |= (received_tag[i] ^ computed_tag[i]);
    }

    /* DEBUG: 打印比较结果 */
    fprintf(stderr, "DEBUG: HMAC match: %s\n", (result == 0) ? "YES" : "NO");

    return (result == 0);
}
```

同样在 `crypto_compute_hmac()` 中添加：

```c
void crypto_compute_hmac(struct crypto_context* ctx,
                         const void* msg, size_t msg_len,
                         void* tag, size_t tag_len)
{
    if (!ctx || !msg || !tag) return;

    unsigned char hmac_output[32];
    unsigned int hmac_len;

    /* DEBUG: 打印 HMAC 密钥 */
    fprintf(stderr, "DEBUG: HMAC key: ");
    for (int i = 0; i < CRYPTO_HMAC_KEY_SIZE; i++) {
        fprintf(stderr, "%02x", ctx->hmac_key[i]);
    }
    fprintf(stderr, "\n");

    HMAC(EVP_sha256(),
         ctx->hmac_key, CRYPTO_HMAC_KEY_SIZE,
         msg, msg_len,
         hmac_output, &hmac_len);

    /* DEBUG: 打印完整 HMAC 输出 */
    fprintf(stderr, "DEBUG: Full HMAC output: ");
    for (int i = 0; i < hmac_len; i++) {
        fprintf(stderr, "%02x", hmac_output[i]);
    }
    fprintf(stderr, "\n");

    size_t copy_len = (tag_len < hmac_len) ? tag_len : hmac_len;
    memcpy(tag, hmac_output, copy_len);
}
```

### 步骤 2: 重新编译

```bash
cd src
make clean
make
```

### 步骤 3: 运行并观察输出

**服务器**:
```bash
sudo ./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e 1 -t aes-128 -n mv0
```

**客户端**:
```bash
sudo ./minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -e 1 -t aes-128 -n mv1
```

**观察**:
- 查看服务器输出的 "DEBUG: HMAC key"
- 查看客户端输出的 "DEBUG: HMAC key"
- **如果两者不同 → 密钥派生有问题**
- 查看 "Received HMAC" vs "Computed HMAC"
- **如果不匹配 → 说明发送方和接收方计算的内容不一致**

---

## 🔍 调试方法 2: 验证密钥派生

### 创建测试程序 test_kdf.c

```c
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        return 1;
    }

    const char *password = argv[1];
    const unsigned char salt[] = "minivtun-v2-salt-2026";
    const int iterations = 100000;
    unsigned char key_material[64];

    printf("Testing PBKDF2 with password: '%s'\n", password);
    printf("Salt: '%s'\n", salt);
    printf("Iterations: %d\n\n", iterations);

    int ret = PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        salt, sizeof(salt) - 1,
        iterations,
        EVP_sha256(),
        sizeof(key_material),
        key_material
    );

    if (ret != 1) {
        fprintf(stderr, "PBKDF2 failed\n");
        return 1;
    }

    printf("Encryption key (first 32 bytes):\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key_material[i]);
    }
    printf("\n\n");

    printf("HMAC key (bytes 32-63):\n");
    for (int i = 32; i < 64; i++) {
        printf("%02x", key_material[i]);
    }
    printf("\n\n");

    return 0;
}
```

### 编译并测试

```bash
gcc -o test_kdf test_kdf.c -lssl -lcrypto
./test_kdf "1"
```

**在服务器和客户端都运行这个测试**，确认派生的密钥是否相同。

---

## 🔍 调试方法 3: 抓包分析

### 步骤 1: 在服务器抓包

```bash
sudo tcpdump -i any -w hmac_test.pcap 'udp port 9999'
```

### 步骤 2: 启动服务器和客户端

### 步骤 3: 分析数据包

```bash
sudo tcpdump -r hmac_test.pcap -X | head -100
```

查看：
- 数据包大小
- 前几个字节（应该是加密后的数据）
- 如果看到明文 → 加密没有工作

---

## 🔍 调试方法 4: 检查 Encrypt-and-MAC 顺序问题

这是我在安全审计中发现的问题。让我们验证这是否是根本原因。

### 创建测试补丁 test_encrypt_then_mac.patch

```c
// 在 client.c tunnel_receiving() 中，临时测试 Encrypt-then-MAC

// 找到这段代码 (大约 200-212 行):
memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
nmsg->hdr.seq = htons(state.xmit_seq++);
nmsg->ipdata.proto = pi->proto;
nmsg->ipdata.ip_dlen = htons(ip_dlen);
memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

// 当前代码 (错误):
if (state.crypto_ctx) {
    size_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
    crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
                        nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
}
out_data = buffers->read_buffer;
out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
    LOG("Encryption failed");
    return 0;
}

// 修改为 (测试 Encrypt-then-MAC):
// 先清零 auth_key
memset(nmsg->hdr.auth_key, 0, sizeof(nmsg->hdr.auth_key));

// 先加密
out_data = buffers->read_buffer;
out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
    LOG("Encryption failed");
    return 0;
}

// 后计算 HMAC (对加密后的数据)
if (state.crypto_ctx) {
    struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)out_data;
    crypto_compute_hmac(state.crypto_ctx, encrypted_msg, out_dlen,
                        encrypted_msg->hdr.auth_key, sizeof(encrypted_msg->hdr.auth_key));
}
```

类似地修改接收方（先验证 HMAC 再解密）。

---

## 🔍 调试方法 5: 简化测试

### 创建最小测试用例

```bash
# 使用最简单的密码
服务器: ./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e "a" -n mv0
客户端: ./minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -e "a" -n mv1
```

### 测试不同的加密算法

```bash
# 测试 1: AES-128 (默认)
-t aes-128

# 测试 2: AES-256
-t aes-256

# 测试 3: DES
-t des

# 测试 4: RC4
-t rc4
```

看看是否所有算法都失败，还是只有某些算法失败。

---

## 🎯 预期的调试输出

### 如果密钥派生正确

服务器和客户端应该输出**相同的**：
```
DEBUG: HMAC key: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### 如果 Encrypt-and-MAC 是问题

你会看到：
```
服务器接收:
DEBUG: Received HMAC: a1b2c3d4e5f67890...
DEBUG: Computed HMAC: f0e1d2c3b4a59687...
DEBUG: HMAC match: NO
```

**原因**: 发送方对明文计算 HMAC，接收方解密后对明文计算 HMAC，但由于加密/解密过程中的某些问题，计算输入不一致。

---

## 🔧 快速验证方案

### 方案 1: 检查 auth_key 是否被加密

在 `crypto_encrypt()` 函数中添加日志：

```c
int crypto_encrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
{
    if (!c_ctx) {
        memmove(out, in, *dlen);
        return 0;
    }

    // DEBUG: 打印加密前的 auth_key
    struct minivtun_msg *msg = (struct minivtun_msg *)in;
    fprintf(stderr, "DEBUG: auth_key before encryption: ");
    for (int i = 0; i < 16; i++) {
        fprintf(stderr, "%02x", msg->hdr.auth_key[i]);
    }
    fprintf(stderr, "\n");

    // ... 原有加密代码 ...

    // DEBUG: 打印加密后的 auth_key
    struct minivtun_msg *enc_msg = (struct minivtun_msg *)out;
    fprintf(stderr, "DEBUG: auth_key after encryption: ");
    for (int i = 0; i < 16; i++) {
        fprintf(stderr, "%02x", enc_msg->hdr.auth_key[i]);
    }
    fprintf(stderr, "\n");

    return ret;
}
```

**预期**: auth_key 应该被加密！如果加密前后一样 → 加密有问题。

---

## 📋 完整的调试脚本

创建文件 `debug_hmac.sh`:

```bash
#!/bin/bash

echo "=== MiniVTun HMAC Debug Script ==="
echo ""

# 检查 Git 版本
echo "1. Checking Git version:"
git log -1 --oneline
echo ""

# 检查是否有未编译的修改
echo "2. Checking for uncommitted changes:"
git status --short
echo ""

# 重新编译
echo "3. Recompiling with debug flags:"
cd src
make clean
make CFLAGS="-g -O0 -DDEBUG"
echo ""

# 测试密钥派生
echo "4. Testing PBKDF2 key derivation:"
cat > /tmp/test_kdf.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main() {
    const char *password = "1";
    const unsigned char salt[] = "minivtun-v2-salt-2026";
    const int iterations = 100000;
    unsigned char key_material[64];

    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt)-1,
                      iterations, EVP_sha256(), sizeof(key_material), key_material);

    printf("HMAC key: ");
    for (int i = 32; i < 64; i++) printf("%02x", key_material[i]);
    printf("\n");
    return 0;
}
EOF
gcc -o /tmp/test_kdf /tmp/test_kdf.c -lssl -lcrypto
/tmp/test_kdf
echo ""

echo "=== Debug setup complete ==="
echo "Now run server and client with -e 1 and observe DEBUG output"
```

运行:
```bash
chmod +x debug_hmac.sh
./debug_hmac.sh
```

---

## 🎯 下一步

请执行 **调试方法 1**（添加详细日志），然后提供：

1. 服务器的调试输出（包括 DEBUG 行）
2. 客户端的调试输出（包括 DEBUG 行）
3. 特别关注：
   - HMAC key 是否相同
   - Received HMAC vs Computed HMAC 的差异
   - Message length 是否相同

有了这些信息，我就能精确定位问题是：
- 密钥派生不一致
- 消息内容不一致
- Encrypt-and-MAC 顺序问题
- 或者其他原因
