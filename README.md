> **Note: This is a modified version.** The original project by Justin Liu can be found at [github.com/rssnsj/minivtun](https://github.com/rssnsj/minivtun). This version has been adapted to include a one-click static compilation script.

# minivtun
*A fast, secure, and reliable VPN service.*

**Author:** Justin Liu <rssnsj@gmail.com>

---

A fast, secure, and reliable VPN service using a non-standard protocol for rapidly deploying VPN servers/clients or getting through firewalls.

### Key Features
* **Fast**: Direct UDP-encapsulated communication without complex authentication handshakes.
* **Secure**: Both header and tunnel data are encrypted, making it difficult to track by protocol characteristics.
* **Reliable**: Communication recovers immediately from the next received packet after a session dies.
* **Rapid to deploy**: A standalone program with all configuration specified via a few command-line options.
* **Portable and Modular**: Can be easily compiled for different platforms and optimized for embedded devices.

### Compilation

This version includes a unified build script that handles all dependencies and can produce a fully static binary for different architectures. Static binaries are ideal for portability and deployment on minimal systems.

**Prerequisites:**
- `wget`
- `tar`
- `git`
- A standard build environment (`make`, `gcc`)

#### **1. Native Static Build (x86_64)**

To compile a static binary for your current `x86_64` Linux system:
```bash
./build.sh
```
The final binary will be named `minivtun_x86_64`.

#### **2. Cross-Compilation for MIPS (Newifi 3 Router)**

To cross-compile a static binary for a `mipsel` device:
```bash
./build.sh mipsel
```
This will produce a MIPS-compatible binary named `minivtun_mipsel`.

For more details on the build process and dependencies, see [COMPILING_STATIC.md](COMPILING_STATIC.md).

#### **3. Traditional Dynamic Build**

If you prefer a traditional dynamic build using your system's libraries (like OpenSSL), you can still use the original makefile.
```bash
cd src
make
sudo make install
```
On **FreeBSD**, use `gmake` instead of `make`.

### Usage

    Mini virtual tunneller in non-standard protocol.
    Usage:
      minivtun [options]
    
    Options:
      -l, --local <ip:port>                 Local IP:port for server to listen.
      -r, --remote <host:port>              Host:port of server to connect.
      -n, --ifname <ifname>                 Virtual interface name (e.g., mv0).
      -a, --ipv4-addr <tun_lip/pfx>         Set tunnel IPv4 address and prefix length.
      -A, --ipv6-addr <tun_ip6/pfx>         Set tunnel IPv6 address and prefix length.
      -m, --mtu <mtu>                       Set tunnel MTU size (default: 1300).
      -Q, --qlen <qlen>                     Set the TX queue length for the tunnel interface.
      -E, --tap                             Enable TAP (L2 Ethernet) mode instead of TUN (L3 IP) mode.
      -d, --daemon                          Run as a daemon process in the background.
      -p, --pidfile <pid_file>              Specify the PID file path when running as a daemon.
      -e, --key <password>                  Shared password for data encryption.
      -t, --algo <cipher>                   Encryption algorithm (see "Encryption Ciphers" section).
      -v, --route <net/pfx>[=gw]            Add a route through the tunnel, can be specified multiple times.
      -w, --wait-dns                        (Client) Wait for DNS to be resolvable before connecting.
      -D, --dynamic-link                    (Client) Do not bring the link up until the first data is received.
      -M, --metric <metric>[++step]         (Client) Set a metric for attached IPv4 routes.
      -T, --table <table_name>              (Client) Define a routing table for attached IPv4 routes.
      -x, --exit-after <seconds>            (Client) Force the client to exit after a specified number of seconds.
      -R, --reconnect-timeo <seconds>       (Client) Max inactive time before reconnecting (default: 47).
      -K, --keepalive <seconds>             (Client) Interval between keep-alive tests (default: 7).
      -S, --health-assess <seconds>         (Client) Interval between health assessments (default: 60).
      -B, --stats-buckets <count>           (Client) Number of buckets for health statistics (default: 3).
      -H, --health-file <path>              (Client) File path for writing real-time health data.
      -P, --max-droprate <1-100>            (Client) Max allowed packet drop percentage (default: 100).
      -X, --max-rtt <ms>                    (Client) Max allowed round-trip time in milliseconds (default: unlimited).
      -h, --help                            Print this help message.


### Examples

**Server**: Run a VPN server on port 1414, with local virtual address 10.7.0.1, client address space 10.7.0.0/24, and encryption password 'Hello':

    minivtun -l 0.0.0.0:1414 -a 10.7.0.1/24 -e Hello -d

**Client**: Connect to the above server (assuming address `vpn.abc.com`), with local virtual address 10.7.0.33:

    minivtun -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello -d

### Encryption Ciphers

The following encryption ciphers are supported:

*   `aes-128` (default)
*   `aes-256`
*   `des`
*   `desx`
*   `rc4`