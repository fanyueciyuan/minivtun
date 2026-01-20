# "Invalid protocol from tun: 0x54" 错误分析和修复

## 🔍 问题分析

### 错误现象

```
minivtun: *** Invalid protocol from tun: 0x54.
PING 10.99.0.1 (10.99.0.1) 56(84) bytes of data.
3 packets transmitted, 0 received, 100% packet loss
```

### 错误原因

**协议值**: 0x54 (十进制 84, ASCII 'T')
**预期值**: 0x0800 (ETH_P_IP) 或 0x86DD (ETH_P_IPV6)

这个错误表示从 TUN 设备读取的数据包格式不正确。

---

## 🐛 根本原因

### IFF_NO_PI 标志的矛盾

**platform_linux.c 第 43 行**:
```c
ifr.ifr_flags |= IFF_NO_PI; // We provide protocol info manually
```

**问题**:
- 注释说 "We provide protocol info manually"（我们手动提供协议信息）
- 但 `IFF_NO_PI` 的实际含义是 "**不包含**协议信息"
- 代码中设置了 `IFF_NO_PI`，但 `client.c` 仍然期望读取 `struct tun_pi` 头

### IFF_NO_PI 的正确含义

- **未设置 IFF_NO_PI**: 内核会在每个包前添加 4 字节的 `struct tun_pi` 头
  ```c
  struct tun_pi {
      __u16 flags;
      __be16 proto;  // ETH_P_IP (0x0800) 或 ETH_P_IPV6 (0x86DD)
  };
  ```

- **设置 IFF_NO_PI**: 内核**不添加**头部，直接读写原始 IP 包

---

## 🔧 解决方案

### 方案 1: 移除 IFF_NO_PI 标志 (推荐)

修改 `src/platform_linux.c` 第 42-43 行:

**修改前**:
```c
ifr.ifr_flags = tap_mode ? IFF_TAP : IFF_TUN;
ifr.ifr_flags |= IFF_NO_PI; // We provide protocol info manually
```

**修改后**:
```c
ifr.ifr_flags = tap_mode ? IFF_TAP : IFF_TUN;
// Remove IFF_NO_PI to let kernel provide protocol info
// ifr.ifr_flags |= IFF_NO_PI;
```

**理由**:
- client.c 和 server.c 都期望有 `struct tun_pi` 头
- 移除 `IFF_NO_PI` 后，内核会正确提供协议信息
- 这是最小改动，不影响其他代码

---

### 方案 2: 修改代码以支持 IFF_NO_PI (更复杂)

如果想保留 `IFF_NO_PI`，需要修改 `client.c` 和 `server.c`:

#### 修改 client.c 的 tunnel_receiving()

**当前代码** (期望有 tun_pi):
```c
rc = read(state.tunfd, pi, buffers->size);
if (rc <= 0) return -1;
if ((size_t)rc < sizeof(struct tun_pi)) return -1;
ip_dlen = (size_t)rc - sizeof(struct tun_pi);

if (pi->proto == htons(ETH_P_IP)) {
    // ...
}
```

**需要改为** (无 tun_pi):
```c
rc = read(state.tunfd, pi + 1, buffers->size - sizeof(struct tun_pi));
if (rc <= 0) return -1;
ip_dlen = (size_t)rc;

// 手动判断协议类型 (检查 IP 版本字段)
unsigned char *ip_packet = (unsigned char *)(pi + 1);
__be16 proto;
if ((ip_packet[0] >> 4) == 4) {
    proto = htons(ETH_P_IP);
} else if ((ip_packet[0] >> 4) == 6) {
    proto = htons(ETH_P_IPV6);
} else {
    LOG("*** Invalid IP version: %d", (ip_packet[0] >> 4));
    return 0;
}
pi->proto = proto;
```

**不推荐**: 改动太大，容易引入新 bug。

---

## ✅ 推荐修复步骤

### 步骤 1: 修改 platform_linux.c

```bash
cd /path/to/minivtun/src
```

编辑 `platform_linux.c`，注释掉第 43 行:

```c
int plat_tun_alloc(char *dev, bool tap_mode)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        PLOG("Failed to open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tap_mode ? IFF_TAP : IFF_TUN;
    // ifr.ifr_flags |= IFF_NO_PI;  // ← 注释掉这一行

    if (dev && *dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        PLOG("ioctl(TUNSETIFF) failed");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}
```

### 步骤 2: 重新编译

```bash
make clean
make
```

### 步骤 3: 重新测试

```bash
# 服务器
sudo ./minivtun -l 0.0.0.0:9999 -a 10.99.0.1/24 -e "test123" -n mv0

# 客户端
sudo ./minivtun -r 192.3.100.20:9999 -a 10.99.0.2/24 -e "test123" -n mv1

# 测试
ping -c 3 10.99.0.1
```

### 预期结果

```
PING 10.99.0.1 (10.99.0.1) 56(84) bytes of data.
64 bytes from 10.99.0.1: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from 10.99.0.1: icmp_seq=2 ttl=64 time=0.089 ms
64 bytes from 10.99.0.1: icmp_seq=3 ttl=64 time=0.095 ms

--- 10.99.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
```

---

## 🔍 调试方法

### 查看实际的协议值

添加调试输出到 `client.c` 第 193 行之前:

```c
// 在 "Invalid protocol from tun" 之前添加
fprintf(stderr, "DEBUG: pi->flags=0x%04x, pi->proto=0x%04x (expected 0x0800 or 0x86DD)\n",
        ntohs(pi->flags), ntohs(pi->proto));
fprintf(stderr, "DEBUG: First 4 bytes: %02x %02x %02x %02x\n",
        ((unsigned char*)pi)[0], ((unsigned char*)pi)[1],
        ((unsigned char*)pi)[2], ((unsigned char*)pi)[3]);
LOG("*** Invalid protocol from tun: 0x%x.", ntohs(pi->proto));
```

### 使用 tcpdump 抓包

```bash
# 在服务器上
sudo tcpdump -i mv0 -n -vv

# 在客户端上
sudo tcpdump -i mv1 -n -vv
```

---

## 📊 原始项目的问题

这个问题**不是由 HMAC 修复引入的**。原始代码 (commit 8fa7424) 也有同样的问题：

```bash
git show 8fa7424:src/platform_linux.c | grep IFF_NO_PI
# 输出: ifr.ifr_flags |= IFF_NO_PI;
```

可能原始作者:
1. 在某些特定内核版本上测试通过
2. 或者从未使用过这个功能
3. 或者注释写错了（应该是 "No protocol info from kernel"）

---

## 🎯 总结

### 问题根源
- `IFF_NO_PI` 标志告诉内核**不提供**协议信息
- 但代码期望**有**协议信息
- 导致读取的数据格式不匹配

### 最佳修复
- 移除 `IFF_NO_PI` 标志
- 让内核提供正确的 `struct tun_pi` 头
- 最小改动，风险最小

### Git 提交信息
```
git commit -m "Remove IFF_NO_PI flag to fix protocol detection

The IFF_NO_PI flag causes the kernel to NOT provide protocol info,
but the code expects struct tun_pi header to be present. This
mismatch causes 'Invalid protocol from tun: 0x54' errors.

Fix: Remove IFF_NO_PI to let kernel provide tun_pi header correctly.

Issue: ping fails with 100% packet loss
Root cause: platform_linux.c:43 sets IFF_NO_PI but client.c expects tun_pi"
```

---

**推荐操作**: 立即应用方案 1 的修复 ✅
