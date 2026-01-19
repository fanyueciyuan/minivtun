# Git Push Commands - HMAC Authentication Fix

## 方法 1: 仅推送已完成的文件 (不含 patch)

由于 client.c 和 server.c 需要应用 patch,当前只推送已完全修复的文件:

```bash
# 添加已修复的文件
git add src/crypto_wrapper.h
git add src/crypto_openssl.c
git add src/crypto_mbedtls.c

# 提交
git commit -m "Add HMAC authentication interface and implementation

Part 1 of HMAC authentication fix:
- Add crypto_compute_hmac() and crypto_verify_hmac() to crypto_wrapper.h
- Implement PBKDF2-SHA256 key derivation (100k iterations)
- Implement HMAC-SHA256 functions
- Separate encryption key and HMAC key
- Support both OpenSSL and mbedTLS backends

Modified Files:
- src/crypto_wrapper.h: Add HMAC interface declarations
- src/crypto_openssl.c: Implement PBKDF2 + HMAC (OpenSSL)
- src/crypto_mbedtls.c: Implement PBKDF2 + HMAC (mbedTLS)

Remaining work:
- Apply HMAC integration to client.c and server.c (use hmac_auth_fix.patch)

See HMAC_FIX_README.md for details"

# 推送
git push origin master
```

---

## 方法 2: 应用 Patch 后完整推送 (推荐)

```bash
# 1. 应用 patch 修改 client.c 和 server.c
patch -p1 < hmac_auth_fix.patch

# 2. 验证编译 (OpenSSL)
cd src && make clean && make && cd ..

# 或者验证 mbedTLS 编译
# cd src && make clean && make CRYPTO_BACKEND=mbedtls && cd ..

# 3. 添加所有 src 修改
git add src/crypto_wrapper.h
git add src/crypto_openssl.c
git add src/crypto_mbedtls.c
git add src/client.c
git add src/server.c

# 4. 查看变更
git diff --cached

# 5. 提交
git commit -m "Fix HMAC authentication mechanism (Critical Security Fix)

Critical Bug:
Original code used memcpy(auth_key, crypto_ctx, 16) which copied
pointer address instead of key material. This broke authentication
completely in encrypted mode.

Security Fixes:
- Implement PBKDF2-SHA256 key derivation (100,000 iterations)
- Implement HMAC-SHA256 message authentication
- Separate encryption and HMAC keys
- Add constant-time HMAC verification
- Secure key material cleanup
- Support both OpenSSL and mbedTLS backends

Modified Files:
- src/crypto_wrapper.h: Add HMAC interface declarations
- src/crypto_openssl.c: Implement PBKDF2 + HMAC (OpenSSL)
- src/crypto_mbedtls.c: Implement PBKDF2 + HMAC (mbedTLS)
- src/client.c: Replace memcmp with crypto_verify_hmac (3 places)
- src/server.c: Replace memcmp with crypto_verify_hmac (3 places)

Impact:
- Before: Authentication broken, program unusable with encryption
- After: Production-ready HMAC authentication (medium-high security)

Breaking Change: Not backward compatible with original version

References:
- Full details: HMAC_FIX_README.md
- Security audit: 安全审计报告.md
- Technical spec: 认证机制修复方案.md

Co-Authored-By: Claude <noreply@anthropic.com>"

# 6. 推送
git push origin master
```

---

## 方法 3: 推送到新分支 (谨慎测试)

```bash
# 1. 创建新分支
git checkout -b hmac-auth-fix

# 2. 应用 patch
patch -p1 < hmac_auth_fix.patch

# 3. 添加修改
git add src/crypto_wrapper.h
git add src/crypto_openssl.c
git add src/crypto_mbedtls.c
git add src/client.c
git add src/server.c

# 4. 提交
git commit -m "Fix HMAC authentication mechanism (Critical Security Fix)

- Implement PBKDF2-SHA256 key derivation
- Implement HMAC-SHA256 message authentication
- Support OpenSSL and mbedTLS backends
- Fix authentication bypass vulnerability

See HMAC_FIX_README.md for full details"

# 5. 推送到新分支
git push origin hmac-auth-fix

# 6. 在 GitHub 上创建 Pull Request
```

---

## 当前 Git 状态

```
已修改文件 (已完成):
  src/crypto_wrapper.h   ✅ 已完成 (添加 HMAC 接口)
  src/crypto_openssl.c   ✅ 已完成 (OpenSSL 实现)
  src/crypto_mbedtls.c   ✅ 已完成 (mbedTLS 实现)
  src/client.c           ⏳ 需应用 patch (3处修改)
  src/server.c           ⏳ 需应用 patch (3处修改)

未跟踪文件 (文档):
  HMAC_FIX_README.md
  认证机制修复方案.md
  安全审计报告.md
  初学者指南.md
  快速开始.md
  HMAC修复应用指南.md
  hmac_auth_fix.patch
  apply_hmac_fix.sh
  push_to_github.sh
  GIT_PUSH_COMMANDS.md
```

---

## 推荐流程

### 选项 A: 分两次推送

**第一次推送** (已完成的文件):
```bash
cd /Users/liyang/VPS/minivtun/minivtun
git add src/crypto_wrapper.h src/crypto_openssl.c src/crypto_mbedtls.c
git commit -m "Add HMAC authentication interface and implementation (Part 1/2)

Co-Authored-By: Claude <noreply@anthropic.com>"
git push origin master
```

**第二次推送** (应用 patch 后):
```bash
patch -p1 < hmac_auth_fix.patch
cd src && make clean && make && cd ..
git add src/client.c src/server.c
git commit -m "Integrate HMAC authentication in client and server (Part 2/2)

Co-Authored-By: Claude <noreply@anthropic.com>"
git push origin master
```

### 选项 B: 一次性完整推送 (推荐)

```bash
cd /Users/liyang/VPS/minivtun/minivtun

# 1. 应用 patch
patch -p1 < hmac_auth_fix.patch

# 2. 测试编译
cd src && make clean && make && cd ..

# 3. 一次性提交所有修改
git add src/crypto_wrapper.h src/crypto_openssl.c src/crypto_mbedtls.c src/client.c src/server.c

# 4. 创建提交
git commit -m "Fix HMAC authentication mechanism (Critical Security Fix)

- Replace broken memcpy(auth_key, crypto_ctx) with proper HMAC
- Implement PBKDF2-SHA256 key derivation (100,000 iterations)
- Implement HMAC-SHA256 message authentication
- Support both OpenSSL and mbedTLS backends
- Add timing-safe verification

Modified: 5 files in src/
Breaking change: Not backward compatible with original version

Co-Authored-By: Claude <noreply@anthropic.com>"

# 5. 推送
git push origin master
```

---

## 注意事项

1. **不要推送文档文件** (.md 结尾的文件)
   - 它们仅供本地参考
   - 如需推送文档,单独创建 docs 分支

2. **删除的 diff.md 文件**:
   ```bash
   git rm diff.md
   git commit -m "Remove obsolete diff.md"
   ```

3. **推送前检查**:
   ```bash
   git status          # 查看状态
   git diff --cached   # 查看暂存的变更
   git log -1 --stat   # 查看最后一次提交
   ```

4. **推送失败处理**:
   ```bash
   # 如果远程有更新
   git pull origin master
   git push origin master
   ```

5. **验证编译**:
   ```bash
   # OpenSSL 版本
   cd src && make clean && make && cd ..

   # mbedTLS 版本
   cd src && make clean && make CRYPTO_BACKEND=mbedtls && cd ..
   ```

---

## 快速执行命令 (复制粘贴)

### 仅推送已完成的文件 (3个文件):

```bash
cd /Users/liyang/VPS/minivtun/minivtun
git add src/crypto_wrapper.h src/crypto_openssl.c src/crypto_mbedtls.c
git commit -m "Add HMAC authentication interface and implementation

- Support OpenSSL and mbedTLS backends
- PBKDF2-SHA256 key derivation (100k iterations)
- HMAC-SHA256 message authentication

Co-Authored-By: Claude <noreply@anthropic.com>"
git push origin master
```

### 完整推送 (包含 patch 的 5 个文件):

```bash
cd /Users/liyang/VPS/minivtun/minivtun
patch -p1 < hmac_auth_fix.patch
cd src && make clean && make && cd ..
git add src/crypto_wrapper.h src/crypto_openssl.c src/crypto_mbedtls.c src/client.c src/server.c
git commit -m "Fix HMAC authentication mechanism (Critical Security Fix)

- Replace broken memcpy with proper HMAC
- Support OpenSSL and mbedTLS backends
- PBKDF2-SHA256 + HMAC-SHA256
- Timing-safe verification

Co-Authored-By: Claude <noreply@anthropic.com>"
git push origin master
```

---

## 修改文件总结

| 文件 | 状态 | 说明 |
|------|------|------|
| src/crypto_wrapper.h | ✅ 已完成 | 添加 HMAC 接口声明 |
| src/crypto_openssl.c | ✅ 已完成 | OpenSSL 后端 HMAC 实现 |
| src/crypto_mbedtls.c | ✅ 已完成 | mbedTLS 后端 HMAC 实现 |
| src/client.c | ⏳ 需 patch | 3 处集成 HMAC 验证 |
| src/server.c | ⏳ 需 patch | 3 处集成 HMAC 验证 |

---

**推荐**: 使用 **完整推送 (选项 B)** 方式,一次性提交所有 5 个文件的修改 ✅
