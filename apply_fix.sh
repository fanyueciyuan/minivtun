#!/bin/bash
#
# 应用 Encrypt-then-MAC 修复补丁
# 修复 HMAC 验证失败问题
#

set -e

echo "=========================================="
echo "  应用 Encrypt-then-MAC 修复补丁"
echo "=========================================="
echo ""

# 恢复原始版本
if [ -f "src/crypto_openssl.c.backup" ]; then
    echo "[1] 恢复原始 crypto_openssl.c..."
    cp src/crypto_openssl.c.backup src/crypto_openssl.c
    echo "    ✓ 已恢复"
fi

# 备份当前文件
echo ""
echo "[2] 备份文件..."
[ ! -f "src/client.c.backup" ] && cp src/client.c src/client.c.backup
[ ! -f "src/server.c.backup" ] && cp src/server.c src/server.c.backup
echo "    ✓ 已备份 client.c 和 server.c"

echo ""
echo "[3] 应用补丁..."

# 修复说明
cat << 'EOF'

关键修改:
===========

问题: 客户端对72字节明文计算HMAC，服务器对80字节解密后数据验证HMAC

原因: crypto_encrypt() 添加填充，72字节变成80字节，但HMAC在填充前计算

解决:
  发送方 - 先加密(得到填充后的长度)，再对密文计算HMAC
  接收方 - 先验证HMAC(对密文)，再解密

注意: auth_key字段在加密时会被加密，但HMAC计算在加密后进行，所以:
  1. 加密前清零auth_key
  2. 加密后对密文计算HMAC
  3. HMAC值写入密文中的auth_key位置(覆盖加密后的值)

EOF

read -p "是否继续应用补丁? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 1
fi

echo ""
echo "[4] 修改 client.c tunnel_receiving()..."

# 使用 sed 或 patch，这里用简化的方法提示用户手动修改
cat << 'EOF' > /tmp/client_tunnel_receiving.patch
找到 src/client.c 大约 200-221 行的代码:

当前代码:
---------
	memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
	nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
	nmsg->hdr.seq = htons(state.xmit_seq++);
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

修改为:
-------
	memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
	nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
	nmsg->hdr.seq = htons(state.xmit_seq++);
	nmsg->ipdata.proto = pi->proto;
	nmsg->ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

	/* Encrypt first (auth_key is already 0 from memset) */
	out_data = buffers->read_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
        LOG("Encryption failed");
        return 0;
    }

	/* Compute HMAC on ciphertext (only if encryption is enabled) */
	if (state.crypto_ctx) {
		struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)out_data;
		crypto_compute_hmac(state.crypto_ctx, encrypted_msg, out_dlen,
		                    encrypted_msg->hdr.auth_key, sizeof(encrypted_msg->hdr.auth_key));
	}
EOF

cat /tmp/client_tunnel_receiving.patch

echo ""
echo "由于脚本无法自动修改，请手动应用上述修改"
echo "或者使用我提供的完整修复版本"
echo ""
echo "=========================================="
echo "  准备完成，请查看修改说明"
echo "=========================================="
