#!/bin/bash
# MiniVTun HMAC Authentication Fix - Auto Patch Script
# Usage: ./apply_hmac_fix.sh

set -e

echo "==================================="
echo "MiniVTun HMAC Authentication Fix"
echo "==================================="
echo ""

# Check if we're in the right directory
if [ ! -f "src/minivtun.c" ]; then
    echo "Error: Please run this script from the minivtun root directory"
    exit 1
fi

# Backup original files
echo "[1/5] Creating backups..."
mkdir -p backup
cp src/client.c backup/client.c.bak
cp src/server.c backup/server.c.bak
echo "  ✓ Backups created in ./backup/"

# Apply client.c patches
echo "[2/5] Patching client.c..."

# Patch 1: network_receiving() - Replace memcmp with crypto_verify_hmac
sed -i.tmp '/if (memcmp(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key)) != 0)/c\
\t/* Verify HMAC authentication */\
\tif (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {\
\t\tLOG("HMAC verification failed - message authentication error");\
\t\treturn 0;\
\t}\
\t/* Original return removed */' src/client.c

# Remove the old return 0 line
sed -i.tmp '/\/\* Original return removed \*\//,+1d' src/client.c

# Patch 2 & 3: Replace memcpy auth_key with crypto_compute_hmac
# This is more complex, using a Python script instead
cat > /tmp/fix_client_hmac.py << 'EOFPYTHON'
import re
import sys

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Fix tunnel_receiving() - around line 198
content = re.sub(
    r'(\tmemcpy\(nmsg->hdr\.auth_key, state\.crypto_ctx, sizeof\(nmsg->hdr\.auth_key\)\);)(\n\tnmsg->ipdata\.proto = pi->proto;)',
    r'\t/* Compute HMAC (auth_key field is currently zero) */\n'
    r'\tsize_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;\n'
    r'\tcrypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,\n'
    r'\t                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));\2',
    content
)

# Fix do_an_echo_request() - around line 226
content = re.sub(
    r'(\tmemcpy\(nmsg->hdr\.auth_key, state\.crypto_ctx, sizeof\(nmsg->hdr\.auth_key\)\);)(\n\tif \(!config\.tap_mode\))',
    r'\t/* Compute HMAC for ECHO request */\n'
    r'\tsize_t msg_len_for_hmac = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);\n'
    r'\tcrypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,\n'
    r'\t                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));\2',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EOFPYTHON

python3 /tmp/fix_client_hmac.py src/client.c
echo "  ✓ client.c patched"

# Apply server.c patches
echo "[3/5] Patching server.c..."

cat > /tmp/fix_server_hmac.py << 'EOFPYTHON'
import re
import sys

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Fix network_receiving() - around line 480
content = re.sub(
    r'if \(memcmp\(nmsg->hdr\.auth_key, state\.crypto_ctx, sizeof\(nmsg->hdr\.auth_key\)\) != 0\)\n\t\treturn 0;',
    r'/* Verify HMAC authentication */\n'
    r'\tif (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {\n'
    r'\t\tLOG("HMAC verification failed from client");\n'
    r'\t\treturn 0;\n'
    r'\t}',
    content
)

# Fix reply_an_echo_ack() - around line 343
content = re.sub(
    r'(\tmemcpy\(nmsg->hdr\.auth_key, state\.crypto_ctx, sizeof\(nmsg->hdr\.auth_key\)\);)(\n\tnmsg->echo = req->echo;)',
    r'\t/* Compute HMAC for ECHO response */\n'
    r'\tsize_t msg_len_for_hmac = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);\n'
    r'\tcrypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,\n'
    r'\t                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));\2',
    content
)

# Fix tunnel_receiving() - around line 634
content = re.sub(
    r'(\tmemcpy\(nmsg->hdr\.auth_key, state\.crypto_ctx, sizeof\(nmsg->hdr\.auth_key\)\);)(\n\tnmsg->ipdata\.proto = pi->proto;)',
    r'\t/* Compute HMAC (auth_key field is currently zero) */\n'
    r'\tsize_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;\n'
    r'\tcrypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,\n'
    r'\t                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));\2',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EOFPYTHON

python3 /tmp/fix_server_hmac.py src/server.c
echo "  ✓ server.c patched"

# Compile
echo "[4/5] Compiling..."
cd src
make clean > /dev/null 2>&1
if make 2>&1 | tee /tmp/minivtun_compile.log; then
    echo "  ✓ Compilation successful"
else
    echo "  ✗ Compilation failed. Check /tmp/minivtun_compile.log"
    echo ""
    echo "Restoring backups..."
    cp ../backup/client.c.bak client.c
    cp ../backup/server.c.bak server.c
    exit 1
fi
cd ..

# Cleanup temp files
rm -f src/*.tmp /tmp/fix_client_hmac.py /tmp/fix_server_hmac.py

echo "[5/5] Running basic tests..."

# Test 1: Check if binary exists
if [ ! -f "src/minivtun" ]; then
    echo "  ✗ Binary not found"
    exit 1
fi

# Test 2: Check help message
if ./src/minivtun -h > /dev/null 2>&1; then
    echo "  ✓ Binary executes correctly"
else
    echo "  ✗ Binary execution failed"
    exit 1
fi

echo ""
echo "========================================="
echo "✓ HMAC Authentication Fix Applied Successfully!"
echo "========================================="
echo ""
echo "Changes made:"
echo "  • crypto_wrapper.h - Added HMAC interface"
echo "  • crypto_openssl.c - Implemented PBKDF2 + HMAC"
echo "  • client.c - 3 fixes (verification + 2 computations)"
echo "  • server.c - 3 fixes (verification + 2 computations)"
echo ""
echo "Next steps:"
echo "  1. Test basic connectivity:"
echo "     Server: sudo ./src/minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e 'test123' -n mv0"
echo "     Client: sudo ./src/minivtun -r 127.0.0.1:9999 -a 10.99.0.2/24 -e 'test123' -n mv1"
echo "     Test:   ping 10.99.0.1"
echo ""
echo "  2. Test wrong password rejection:"
echo "     Client: sudo ./src/minivtun -r 127.0.0.1:9999 -a 10.99.0.3/24 -e 'wrong' -n mv2"
echo "     Expected: Connection fails with HMAC error"
echo ""
echo "  3. Install (optional):"
echo "     sudo make -C src install"
echo ""
echo "Backups saved in: ./backup/"
echo "To rollback: cp backup/*.bak src/"
echo ""
