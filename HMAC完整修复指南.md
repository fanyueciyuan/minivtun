# 🔧 HMAC 验证失败 - 完整修复指南

## 问题根本原因 (已确认)

通过调试输出确认：

**客户端**:
- 对 **72 字节** 明文计算 HMAC: `ffcfd5aa9d804b1ddf88b67c0dbf667d`
- 加密后变成 **80 字节** (填充)

**服务器**:
- 接收 **80 字节** 密文
- 解密后仍是 **80 字节**
- 对 **80 字节** 重新计算 HMAC: `3abca0bd5cb8c44469c674344eebd8d2`
- **不匹配!** → `HMAC verification failed`

**根本问题**:
- `crypto_encrypt()` 添加填充(padding)导致长度变化
- 客户端对填充前的长度计算 HMAC
- 服务器对填充后的长度验证 HMAC
- 长度不一致 → HMAC 不匹配

---

## 修复方案: Encrypt-then-MAC

**原则**: HMAC 必须基于**相同长度**的数据计算

**修改**:
- 发送方: 先加密 → 再对**密文**计算 HMAC (使用加密后的长度)
- 接收方: 先验证**密文**的 HMAC → 再解密

---

## 具体修改步骤

### 修改 1: src/client.c - tunnel_receiving() 函数

**位置**: 大约第 200-221 行

**查找以下代码**:
```c
	nmsg->ipdata.proto = pi->proto;
	nmsg->ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
	/* Compute HMAC (only if encryption is enabled) */
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

	(void)send(state.sockfd, out_data, out_dlen, 0);
```

**替换为**:
```c
	nmsg->ipdata.proto = pi->proto;
	nmsg->ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

	/* Encrypt first (auth_key already zero from memset above) */
	out_data = buffers->read_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
        LOG("Encryption failed");
        return 0;
    }

	/* Compute HMAC on ciphertext with actual encrypted length */
	if (state.crypto_ctx) {
		struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)out_data;
		crypto_compute_hmac(state.crypto_ctx, encrypted_msg, out_dlen,
		                    encrypted_msg->hdr.auth_key, sizeof(encrypted_msg->hdr.auth_key));
	}

	(void)send(state.sockfd, out_data, out_dlen, 0);
```

**关键变化**:
1. 移除HMAC计算（之前在加密前）
2. 先执行 `local_to_netmsg()` 加密，`out_dlen` 会被更新为填充后的长度
3. 对加密后的数据(`encrypted_msg`)计算HMAC，使用实际的 `out_dlen`

---

### 修改 2: src/client.c - do_an_echo_request() 函数

**位置**: 大约第 235-262 行

**查找**:
```c
	/* Fill echo fields BEFORE computing HMAC */
	if (!config.tap_mode) {
		nmsg->echo.loc_tun_in = config.tun_in_local;
#if WITH_IPV6
		nmsg->echo.loc_tun_in6 = config.tun_in6_local;
#endif
	}
	nmsg->echo.id = r;
	/* Compute HMAC for ECHO request (only if encryption is enabled) */
	if (state.crypto_ctx) {
		msg_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
		crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len,
		                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
	}

	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	(void)send(state.sockfd, out_msg, out_len, 0);
```

**替换为**:
```c
	/* Fill echo fields */
	if (!config.tap_mode) {
		nmsg->echo.loc_tun_in = config.tun_in_local;
#if WITH_IPV6
		nmsg->echo.loc_tun_in6 = config.tun_in6_local;
#endif
	}
	nmsg->echo.id = r;

	/* Encrypt first */
	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	/* Compute HMAC on ciphertext (only if encryption is enabled) */
	if (state.crypto_ctx) {
		struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)out_msg;
		crypto_compute_hmac(state.crypto_ctx, encrypted_msg, out_len,
		                    encrypted_msg->hdr.auth_key, sizeof(encrypted_msg->hdr.auth_key));
	}

	(void)send(state.sockfd, out_msg, out_len, 0);
```

---

### 修改 3: src/client.c - network_receiving() 函数

**位置**: 大约第 87-109 行

**查找**:
```c
	rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0,
			(struct sockaddr *)&real_peer, &real_peer_alen);
	if (rc <= 0)
		return -1;

	out_data = buffers->crypt_buffer;
	out_dlen = (size_t)rc;
	if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
        LOG("Decryption failed.");
        return 0;
    }
	nmsg = out_data;

	if (out_dlen < MINIVTUN_MSG_BASIC_HLEN)
		return 0;

	/* Verify HMAC authentication (only if encryption is enabled) */
	if (state.crypto_ctx) {
		if (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {
			LOG("HMAC verification failed - message authentication error");
			return 0;
		}
	}
```

**替换为**:
```c
	rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0,
			(struct sockaddr *)&real_peer, &real_peer_alen);
	if (rc <= 0)
		return -1;

	/* Verify HMAC on ciphertext BEFORE decryption */
	if (state.crypto_ctx) {
		struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)buffers->read_buffer;
		if (!crypto_verify_hmac(state.crypto_ctx, encrypted_msg, (size_t)rc)) {
			LOG("HMAC verification failed - message authentication error");
			return 0;
		}
	}

	out_data = buffers->crypt_buffer;
	out_dlen = (size_t)rc;
	if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
        LOG("Decryption failed.");
        return 0;
    }
	nmsg = out_data;

	if (out_dlen < MINIVTUN_MSG_BASIC_HLEN)
		return 0;
```

**关键变化**:
1. HMAC验证移到解密**之前**
2. 对密文(`encrypted_msg`)验证，使用接收到的原始长度 `rc`
3. 验证通过后才解密

---

### 修改 4-6: src/server.c 的对应修改

**server.c 需要进行完全相同的3处修改**:

#### 修改 4: server.c - tunnel_receiving() (大约 640-661行)
与 client.c 的修改 1 相同模式

#### 修改 5: server.c - reply_an_echo_ack() (大约 340-359行)
与 client.c 的修改 2 相同模式

#### 修改 6: server.c - network_receiving() (大约 470-492行)
与 client.c 的修改 3 相同模式

---

## 编译和测试

### 1. 恢复调试版本（如果需要）
```bash
./restore_crypto.sh  # 如果之前启用了调试版本
```

### 2. 重新编译
```bash
cd src
make clean
make
```

### 3. 测试无加密模式（确保基本功能正常）
```bash
# 服务器
sudo ./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -n mv0

# 客户端
sudo ./minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -n mv1

# 测试
ping -c 3 10.99.0.1  # 应该成功
```

### 4. 测试加密模式
```bash
# 服务器
sudo ./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e "1" -t aes-128 -n mv0

# 客户端
sudo ./minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -e "1" -t aes-128 -n mv1

# 测试
ping -c 5 10.99.0.1  # 现在应该成功！
```

**预期结果**:
```
5 packets transmitted, 5 received, 0% packet loss ✅
```

**如果仍然失败**，启用调试版本查看 HMAC 是否现在匹配。

---

## 验证修复

修复后，调试输出应该显示：

**客户端**:
```
Message length: 80  ← 加密后的长度
Computed HMAC: XXXXXXXX...
```

**服务器**:
```
Message length: 80  ← 相同的长度
Received HMAC: XXXXXXXX...  ← 来自客户端
Computed HMAC: XXXXXXXX...  ← 相同！
HMAC match: YES ✓
```

---

## 如果手动修改太复杂

我可以为你生成完整修复后的 `client.c` 和 `server.c` 文件。请告诉我是否需要。

---

## 总结

**修复的核心原则**:
1. **发送**: 先加密 → 后计算HMAC（基于加密后的实际长度）
2. **接收**: 先验证HMAC → 验证通过再解密

**为什么这样修复有效**:
- 加密会添加填充，导致长度变化（72→80）
- HMAC在加密后计算，基于填充后的长度（80字节）
- 接收方验证HMAC也是基于相同的长度（80字节）
- **长度一致 → HMAC匹配 → 验证成功！**

**额外好处**:
- ✅ 防止填充预言攻击
- ✅ 防止DoS攻击（先验证HMAC，拒绝伪造消息无需解密）
- ✅ 符合业界标准（RFC 7366 Encrypt-then-MAC）
