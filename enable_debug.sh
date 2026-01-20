#!/bin/bash
#
# HMAC Debug 测试脚本
# 用于快速启用调试版本并测试 HMAC 问题
#

set -e

echo "=========================================="
echo "   MiniVTun HMAC Debug 测试工具"
echo "=========================================="
echo ""

# 检查是否在正确的目录
if [ ! -f "src/crypto_openssl.c" ]; then
    echo "错误: 请在 minivtun 项目根目录运行此脚本"
    exit 1
fi

# 备份原始文件
echo "[1] 备份原始 crypto_openssl.c..."
if [ ! -f "src/crypto_openssl.c.backup" ]; then
    cp src/crypto_openssl.c src/crypto_openssl.c.backup
    echo "    ✓ 已创建备份: src/crypto_openssl.c.backup"
else
    echo "    ✓ 备份已存在"
fi

# 使用调试版本
echo ""
echo "[2] 启用调试版本..."
cp src/crypto_openssl_debug.c src/crypto_openssl.c
echo "    ✓ 已替换为调试版本"

# 重新编译
echo ""
echo "[3] 重新编译..."
cd src
make clean > /dev/null 2>&1
make
if [ $? -eq 0 ]; then
    echo "    ✓ 编译成功"
else
    echo "    ✗ 编译失败"
    exit 1
fi
cd ..

# 创建测试密钥工具
echo ""
echo "[4] 创建密钥派生测试工具..."
cat > /tmp/test_pbkdf2.c << 'EOF'
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

    printf("=== PBKDF2 Key Derivation Test ===\n");
    printf("Password: '%s'\n", password);
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

    printf("Encryption key (first 16 bytes for AES-128):\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x", key_material[i]);
    }
    printf("\n\n");

    printf("HMAC key (bytes 32-63):\n");
    for (int i = 32; i < 64; i++) {
        printf("%02x", key_material[i]);
    }
    printf("\n\n");

    printf("=== Run this on both server and client ===\n");
    printf("Keys should be IDENTICAL!\n");

    return 0;
}
EOF

gcc -o /tmp/test_pbkdf2 /tmp/test_pbkdf2.c -lssl -lcrypto 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    ✓ 已创建: /tmp/test_pbkdf2"
else
    echo "    ✗ 创建失败"
fi

echo ""
echo "=========================================="
echo "           调试准备完成！"
echo "=========================================="
echo ""
echo "📋 测试步骤:"
echo ""
echo "1️⃣  测试密钥派生 (在服务器和客户端都运行):"
echo "    /tmp/test_pbkdf2 \"1\""
echo "    → 确认两端输出的 HMAC key 完全一致"
echo ""
echo "2️⃣  启动服务器 (会显示调试信息):"
echo "    sudo ./src/minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e \"1\" -t aes-128 -n mv0"
echo ""
echo "3️⃣  启动客户端 (会显示调试信息):"
echo "    sudo ./src/minivtun -r SERVER_IP:9999 -a 10.99.0.2/24 -e \"1\" -t aes-128 -n mv1"
echo ""
echo "4️⃣  观察调试输出:"
echo "    - 查看 'DEBUG: crypto_init()' 的 HMAC key"
echo "    - 查看 'DEBUG: crypto_compute_hmac()' 的输出"
echo "    - 查看 'DEBUG: crypto_verify_hmac()' 的对比"
echo ""
echo "5️⃣  完成测试后恢复原始版本:"
echo "    ./restore_crypto.sh"
echo ""
echo "=========================================="
echo ""

# 创建恢复脚本
cat > restore_crypto.sh << 'EOF'
#!/bin/bash
echo "恢复原始 crypto_openssl.c..."
if [ -f "src/crypto_openssl.c.backup" ]; then
    cp src/crypto_openssl.c.backup src/crypto_openssl.c
    echo "✓ 已恢复原始版本"
    cd src
    make clean > /dev/null 2>&1
    make
    echo "✓ 重新编译完成"
else
    echo "✗ 未找到备份文件"
    exit 1
fi
EOF
chmod +x restore_crypto.sh

echo "💡 提示: 调试输出会很多，建议重定向到文件:"
echo "    sudo ./src/minivtun ... 2> server_debug.log"
echo "    sudo ./src/minivtun ... 2> client_debug.log"
echo ""
