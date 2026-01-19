diff --git a/README.md b/README.md
index a013bb3..025b9a9 100644
--- a/README.md
+++ b/README.md
@@ -1,46 +1,49 @@
 # minivtun
-A fast secure and reliable VPN service in non-standard protocol for rapidly deploying VPN servers/clients or getting through firewalls
+A fast, secure, and reliable VPN service using a non-standard protocol for rapidly deploying VPN servers/clients or getting through firewalls.
 
 ### Key features
-* Fast: direct UDP-encapsulated without complex authentication handshakes.
-* Secure: both header and tunnel data are encrypted, which is nearly impossible to be tracked by protocol characteristics and blocked, unless all UDP ports are blocked by your firewall; spoofed packets from unauthorized peer are dropped immediately.
-* Reliable: communication recovers immediately from next received packet from client after the previous session was dead, which makes the connection extremely reliable.
-* Rapid to deploy: a standalone program to run; all configuration are specified in command line with very few options.
+* **Fast**: Direct UDP-encapsulated communication without complex authentication handshakes.
+* **Secure**: Both header and tunnel data are encrypted, making it difficult to track by protocol characteristics.
+* **Reliable**: Communication recovers immediately from the next received packet after a session dies.
+* **Rapid to deploy**: A standalone program with all configuration specified via a few command-line options.
+* **Portable and Modular**: Can be easily compiled for different platforms and optimized for embedded devices by including or excluding features.
 
+### Installation
 
-### Installation for Linux
+Install required development components (e.g., `build-essential`, `libssl-dev` on Debian/Ubuntu or `gcc`, `openssl-devel` on CentOS/Fedora). Then compile and install:
 
-Install required development components
- 
-    sudo apt-get install build-essential libssl-dev   # for Ubuntu / Debian
-    sudo yum install make gcc openssl-devel   # for CentOS / Fedora / RedHat
-  
-Compile and install
- 
-    git clone https://github.com/rssnsj/minivtun.git minivtun
     cd minivtun/src
     make
     sudo make install
 
-### Installation for Mac OS X
+For **Mac OS X**, you may need to first install the [TUNTAP driver](http://tuntaposx.sourceforge.net/).
+For **FreeBSD**, use `gmake` instead of `make`.
 
-Install TUNTAP driver for Mac OS X: http://tuntaposx.sourceforge.net/
- 
-Compile and install
- 
-    git clone https://github.com/rssnsj/minivtun.git minivtun
-    cd minivtun/src
-    make
-    sudo make install
- 
-### Installation for FreeBSD
- 
-Compile and install
- 
-    git clone https://github.com/rssnsj/minivtun.git minivtun
-    cd minivtun/src
-    gmake
-    sudo gmake install
+### Cross-compilation and Embedded Builds
+ 
+The build system allows for modular compilation to produce an optimized binary. This is useful for cross-compilation and for creating minimal builds for resource-constrained embedded devices.
+ 
+You can control which features to include by passing variables to the `make` command.
+ 
+**Build Options:**
+ 
+| Variable            | Description                                       | Default |
+|---------------------|---------------------------------------------------|---------|
+| `WITH_IPV6`         | Include IPv6 support.                             | `yes`   |
+| `WITH_CLIENT_MODE`  | Include client mode code.                         | `yes`   |
+| `WITH_SERVER_MODE`  | Include server mode code.                         | `yes`   |
+| `WITH_DAEMONIZE`    | Include the ability to run as a daemon.           | `yes`   |
+| `OPTIMIZE_FOR_SIZE` | Optimize for the smallest binary size.            | `no`    |
+| `NO_LOG`            | Disable all log output to reduce binary size.     | `no`    |
+| `PLATFORM`          | Target platform (`linux` or `bsd`).               | auto    |
+| `CRYPTO_BACKEND`    | Cryptography backend to use.                      | `openssl`|
+ 
+**Example: Minimal client-only build for an embedded Linux system**
+ 
+This command creates a small, client-only binary without IPv6 or daemonization support and strips all unnecessary symbols.
+ 
+    make WITH_IPV6=no WITH_SERVER_MODE=no WITH_DAEMONIZE=no OPTIMIZE_FOR_SIZE=yes NO_LOG=yes
 
 ### Usage
 
-### Installation
- 
-Install required development components
- 
-    sudo apt-get install build-essential libssl-dev   # for Ubuntu / Debian
-    sudo yum install make gcc openssl-devel   # for CentOS / Fedora / RedHat
-  
-Compile and install
- 
-    git clone https://github.com/rssnsj/minivtun.git minivtun
-    cd minivtun/src
-    make
-    sudo make install
- 
-### Installation for Mac OS X
- 
-Install TUNTAP driver for Mac OS X: http://tuntaposx.sourceforge.net/
- 
-Compile and install
- 
-    git clone https://github.com/rssnsj/minivtun.git minivtun
-    cd minivtun/src
-    make
-    sudo make install
- 
-### Installation for FreeBSD
- 
-Compile and install
- 
-    git clone https://github.com/rssnsj/minivtun.git minivtun
-    cd minivtun/src
-    gmake
-    sudo gmake install
+       Options:
+         -l, --local <ip:port>               IP:port for server to listen
+         -r, --remote <ip:port>              IP:port of server to connect
+         -a, --ipv4-addr <tun_lip/pfx_len>   IPv4 address/prefix length pair
+         -A, --ipv6-addr <tun_ip6/pfx_len>   IPv6 address/prefix length pair
+         -m, --mtu <mtu>                     set MTU size, default: 1300.
+      -t, --algo <cipher>                 encryption algorithm (e.g., aes-128, default)
+         -n, --ifname <ifname>               virtual interface name
+         -p, --pidfile <pid_file>            PID file of the daemon
+         -e, --key <encryption_key>          shared password for data encryption
+         -v, --route <network/prefix=gateway> 
+                                              route a network to a client address, can be multiple
+         -w, --wait-dns                      wait for DNS resolve ready after service started.
+         -d, --daemon                        run as daemon process
+         -E, --tap                           TAP mode
+         -D, --dynamic-link                  dynamic link mode, not bring up until data received
+         -M, --metric <metric>[++stepping]   metric of attached IPv4 routes
+         -T, --table <table_name>            route table of the attached IPv4 routes
+         -x, --exit-after <N>                force the client to exit after N seconds
+         -H, --health-file <file_path>       file for writing real-time health data
+         -R, --reconnect-timeo <N>           maximum inactive time (seconds) before reconnect, default: 60
+         -K, --keepalive <N>                 seconds between keep-alive tests, default: 10
+         -S, --health-assess <N>             seconds between health assess, default: 5
+         -B, --stats-buckets <N>             health data buckets, default: 5
+         -P, --max-droprate <1~100>          maximum allowed packet drop percentage, default: 10%
+         -X, --max-rtt <N>                   maximum allowed echo delay (ms), default: unlimited
+         -h, --help                          print this help
 
-### Examples
+**Server**: Run a VPN server on port 1414, with local virtual address 10.7.0.1, client address space 10.7.0.0/24, and encryption password 'Hello':
 
-    /usr/sbin/minivtun -l 0.0.0.0:1414 -a 10.7.0.1/24 -e Hello -d
+    /usr/sbin/minivtun -l 0.0.0.0:1414 -a 10.7.0.1/24 -e Hello -d
 
-Client: Connect VPN to the above server (assuming address vpn.abc.com), with local virtual address 10.7.0.33:
+**Client**: Connect to the above server (assuming address `vpn.abc.com`), with local virtual address 10.7.0.33:
 
-    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello -d
+    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello -d
 
-Multiple clients on different devices can be connected to the same server:
- 
-    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.34/24 -e Hello -d
-    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.35/24 -e Hello -d
-    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.36/24 -e Hello -d
-    ...
- 
-### Diagnoses
- 
-None.
+diff --git a/src/Makefile b/src/Makefile
index 0a62ebd..31db3bb 100644
--- a/src/Makefile
+++ b/src/Makefile
@@ -3,24 +3,113 @@
 # Author: Justin Liu <rssnsj@gmail.com>
 # https://github.com/rssnsj/minivtun
 #
+# Advanced Makefile for modular builds
+#
 
-ifeq ($(PREFIX),)
-PREFIX := $(shell [ -d /opt/local ] && echo /opt/local || echo /usr )
-endif
+# Customizable Prefix
+# ---------------------------------
+PREFIX ?= /usr/local
+ 
+# Build Configuration
+# ---------------------------------
+# Set to 'yes' to enable features, 'no' to disable
+WITH_IPV6          ?= yes
+WITH_DAEMONIZE     ?= yes
+WITH_CLIENT_MODE   ?= yes
+WITH_SERVER_MODE   ?= yes
+OPTIMIZE_FOR_SIZE  ?= no
+NO_LOG             ?= no
+ 
+# Backend Selection
+# ---------------------------------
+CRYPTO_BACKEND     ?= openssl
+# PLATFORM is auto-detected, but can be overridden (e.g., PLATFORM=linux)
+UNAME_S := $(shell uname -s)
+ifeq ($(UNAME_S),Linux)
+    PLATFORM ?= linux
+endif
+ifeq ($(UNAME_S),FreeBSD)
+    PLATFORM ?= bsd
+endif
+ifeq ($(UNAME_S),Darwin)
+    PLATFORM ?= bsd
+endif
+PLATFORM ?= linux # Default to linux if detection fails
+ 
+# Compiler and Flags
+# ---------------------------------
+CC ?= gcc
+CFLAGS += -Wall
+LDFLAGS ?= 
+ 
+# Feature Flags
+# ---------------------------------
+CFLAGS += -DWITH_IPV6=$(if $(filter yes,$(WITH_IPV6)),1,0)
+CFLAGS += -DWITH_DAEMONIZE=$(if $(filter yes,$(WITH_DAEMONIZE)),1,0)
+CFLAGS += -DWITH_CLIENT_MODE=$(if $(filter yes,$(WITH_CLIENT_MODE)),1,0)
+CFLAGS += -DWITH_SERVER_MODE=$(if $(filter yes,$(WITH_SERVER_MODE)),1,0)
+ 
+ifeq ($(NO_LOG),yes)
+    CFLAGS += -DNO_LOG=1
+endif
+ 
+# Optimization Flags
+# ---------------------------------
+ifeq ($(OPTIMIZE_FOR_SIZE),yes)
+    CFLAGS += -Os -ffunction-sections -fdata-sections
+    LDFLAGS += -Wl,--gc-sections
+    STRIP_FLAG = yes
+else
+    CFLAGS += -g
+endif
+ 
+# Source Files
+# ---------------------------------
+SRCS = minivtun.o library.o
+ 
+# Platform sources
+SRCS += platform_$(PLATFORM).o
+ 
+# Feature sources
+ifeq ($(WITH_CLIENT_MODE),yes)
+    SRCS += client.o
+endif
+ifeq ($(WITH_SERVER_MODE),yes)
+    SRCS += server.o
+endif
+ 
+# Crypto backend sources and libs
+ifeq ($(CRYPTO_BACKEND),openssl)
+    SRCS += crypto_openssl.o
+    LDLIBS += -lcrypto
+else
+    $(error Unsupported CRYPTO_BACKEND: $(CRYPTO_BACKEND))
+endif
+ 
+ 
+HEADERS = minivtun.h library.h list.h jhash.h platform.h crypto_wrapper.h log.h
+ 
+# Targets
+# ---------------------------------
+.PHONY: all clean install uninstall
+ 
+all: minivtun
+ 
+minivtun: $(SRCS)
+    $(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
+ 
+%.o: %.c $(HEADERS)
+    $(CC) $(CFLAGS) -c -o $@ $<
+ 
+install: minivtun
+    install -d $(DESTDIR)$(PREFIX)/sbin
+    install -m 755 minivtun $(DESTDIR)$(PREFIX)/sbin/
+ifeq ($(STRIP_FLAG),yes)
+    strip $(DESTDIR)$(PREFIX)/sbin/minivtun
+endif
+ 
+uninstall:
+    rm -f $(DESTDIR)$(PREFIX)/sbin/minivtun
+ 
 clean:
-    rm -f minivtun *.o
+    rm -f minivtun *.o
+
diff --git a/src/client.c b/src/client.c
index 1cfa052..b8c802e 100644
--- a/src/client.c
+++ b/src/client.c
@@ -4,6 +4,8 @@
  * https://github.com/rssnsj/minivtun
  */
 
+#if WITH_CLIENT_MODE
+
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -17,33 +19,40 @@
 #include <sys/uio.h>
 
 #include "minivtun.h"
+#include "platform.h"
 
 static bool rewind_dynamic_link_metric = false;
 
+struct client_buffers {
+    size_t size;
+    char *read_buffer;
+    char *crypt_buffer;
+    char *tun_buffer;
+};
+
 static void handle_link_up(void)
 {
 	struct vt_route *rt;
 
-       ip_link_set_updown(config.ifname, true);
+       plat_ip_link_set_updown(config.ifname, true);
 
 	if (config.metric_stepping) {
-               syslog(LOG_INFO, "Link is up, metric: %u.", state.rt_metric);
+               LOG("Link is up, metric: %u.", state.rt_metric);
 	} else {
-               syslog(LOG_INFO, "Link is up.");
+               LOG("Link is up.");
 	}
 
 	/* Add IPv4 address if possible */
-       ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
+       plat_ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
 			&config.tun_in_peer, config.tun_in_prefix);
 
 	/* Add IPv6 address if possible */
-       ip_addr_add_ipv6(config.ifname, &config.tun_in6_local,
+       plat_ip_addr_add_ipv6(config.ifname, &config.tun_in6_local,
 			config.tun_in6_prefix);
+#if WITH_IPV6
+
+#endif
 
 	if (!config.tap_mode) {
-		/* Attach the dynamic routes */
 		for (rt = config.vt_routes; rt; rt = rt->next) {
-                       ip_route_add_ipvx(config.ifname, rt->af, &rt->network, rt->prefix,
+                       plat_ip_route_add(rt->af, config.ifname, &rt->network, rt->prefix,
 				state.rt_metric, config.vt_table[0] ? config.vt_table : NULL);
 		}
 	}
@@ -51,52 +60,51 @@ static void handle_link_up(void)
 
 static void handle_link_down(void)
 {
-       ip_link_set_updown(config.ifname, false);
+       plat_ip_link_set_updown(config.ifname, false);
 
-	/* Lower route priority of the link by adding the stepping factor */
 	state.rt_metric += config.metric_stepping;
 
-       syslog(LOG_INFO, "Link is down.");
+       LOG("Link is down.");
 }
 
-static int network_receiving(void)
+static int network_receiving(struct client_buffers *buffers)
 {
-       char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
+       char pi_buf[sizeof(struct tun_pi)];
+       struct tun_pi* pi = (struct tun_pi*)pi_buf;
 	struct minivtun_msg *nmsg;
-       struct tun_pi pi;
 	void *out_data;
 	size_t ip_dlen, out_dlen;
 	struct sockaddr_inx real_peer;
 	socklen_t real_peer_alen;
 	struct iovec iov[2];
+       struct timeval __current;
 	int rc;
 
 	gettimeofday(&__current, NULL);
 
 	real_peer_alen = sizeof(real_peer);
-       rc = recvfrom(state.sockfd, &read_buffer, NM_PI_BUFFER_SIZE, 0,
+       rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0,
 			(struct sockaddr *)&real_peer, &real_peer_alen);
 	if (rc <= 0)
 		return -1;
 
-       out_data = crypt_buffer;
+       out_data = buffers->crypt_buffer;
 	out_dlen = (size_t)rc;
-       netmsg_to_local(read_buffer, &out_data, &out_dlen);
+       if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
+        LOG("Decryption failed.");
+        return 0;
+    }
 	nmsg = out_data;
 
 	if (out_dlen < MINIVTUN_MSG_BASIC_HLEN)
 		return 0;
 
-	/* Verify password. */
-       if (memcmp(nmsg->hdr.auth_key, config.crypto_key,
-               sizeof(nmsg->hdr.auth_key)) != 0)
+       if (memcmp(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key)) != 0)
 		return 0;
 
 	state.last_recv = __current;
 
 	if (!state.health_based_link_up) {
-		/* Call link-up scripts */
 		if (!state.is_link_ok) {
 			if (config.dynamic_link)
 				handle_link_up();
@@ -70,52 +78,51 @@ static int network_receiving(void)
 	switch (nmsg->hdr.opcode) {
 	case MINIVTUN_MSG_IPDATA:
 		if (config.tap_mode) {
-                       /* No ethernet packet is shorter than 14 bytes. */
-                       if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 14)
-                               return 0;
+                       if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 14) return 0;
 			ip_dlen = out_dlen - MINIVTUN_MSG_IPDATA_OFFSET;
 			nmsg->ipdata.proto = 0;
 		} else {
-			if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
-                               /* No valid IP packet is shorter than 20 bytes. */
-                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20)
-                                       return 0;
-                       } else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
-                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 40)
-                                       return 0;
-                       } else {
-                               syslog(LOG_WARNING, "*** Invalid protocol: 0x%x.", ntohs(nmsg->ipdata.proto));
+                       if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
+                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20) return 0;
+                       }
+#if WITH_IPV6
+            else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
+                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 40) return 0;
+                       }
+#endif
+            else {
+                               LOG("*** Invalid protocol: 0x%x.", ntohs(nmsg->ipdata.proto));
 				return 0;
 			}
 
 			ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
-			/* Drop incomplete IP packets. */
 			if (out_dlen - MINIVTUN_MSG_IPDATA_OFFSET < ip_dlen)
 				return 0;
 		}
 
-		pi.flags = 0;
-		pi.proto = nmsg->ipdata.proto;
-		osx_ether_to_af(&pi.proto);
-		iov[0].iov_base = &pi;
-		iov[0].iov_len = sizeof(pi);
-		iov[1].iov_base = (char *)nmsg + MINIVTUN_MSG_IPDATA_OFFSET;
+		pi->flags = 0;
+		pi->proto = nmsg->ipdata.proto;
+		iov[0].iov_base = pi;
+		iov[0].iov_len = sizeof(*pi);
+		iov[1].iov_base = nmsg->ipdata.data;
 		iov[1].iov_len = ip_dlen;
 		rc = writev(state.tunfd, iov, 2);
 		break;
@@ -123,52 +131,51 @@ static int network_receiving(void)
 	return 0;
 }
 
-static int tunnel_receiving(void)
+static int tunnel_receiving(struct client_buffers *buffers)
 {
-       char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
-       struct tun_pi *pi = (void *)read_buffer;
-       struct minivtun_msg nmsg;
+       struct minivtun_msg *nmsg = (struct minivtun_msg *)buffers->crypt_buffer;
+       struct tun_pi *pi = (struct tun_pi *)buffers->tun_buffer;
 	void *out_data;
 	size_t ip_dlen, out_dlen;
 	int rc;
 
-       rc = read(state.tunfd, pi, NM_PI_BUFFER_SIZE);
-       if (rc < sizeof(struct tun_pi))
-               return -1;
-
-       osx_af_to_ether(&pi->proto);
+       rc = read(state.tunfd, pi, buffers->size);
+       if (rc <= 0) return -1;
+       if ((size_t)rc < sizeof(struct tun_pi)) return -1;
 
 	ip_dlen = (size_t)rc - sizeof(struct tun_pi);
 
 	if (config.tap_mode) {
-		/* No ethernet packet is shorter than 14 bytes. */
-		if (ip_dlen < 14)
-                       return 0;
+               if (ip_dlen < 14) return 0;
 	} else {
-		/* We only accept IPv4 or IPv6 frames. */
 		if (pi->proto == htons(ETH_P_IP)) {
-                       if (ip_dlen < 20)
-                               return 0;
-               } else if (pi->proto == htons(ETH_P_IPV6)) {
-                       if (ip_dlen < 40)
-                               return 0;
-               } else {
-                       syslog(LOG_WARNING, "*** Invalid protocol: 0x%x.", ntohs(pi->proto));
+                       if (ip_dlen < 20) return 0;
+               }
+#if WITH_IPV6
+            else if (pi->proto == htons(ETH_P_IPV6)) {
+                       if (ip_dlen < 40) return 0;
+               }
+#endif
+            else {
+                       LOG("*** Invalid protocol from tun: 0x%x.", ntohs(pi->proto));
 			return 0;
 		}
 	}
 
-\tmemset(&nmsg.hdr, 0x0, sizeof(nmsg.hdr));
-	nmsg.hdr.opcode = MINIVTUN_MSG_IPDATA;
-	nmsg.hdr.seq = htons(state.xmit_seq++);
-	memcpy(nmsg.hdr.auth_key, config.crypto_key, sizeof(nmsg->hdr.auth_key));
-	nmsg.ipdata.proto = pi->proto;
-	nmsg.ipdata.ip_dlen = htons(ip_dlen);
-	memcpy(nmsg.ipdata.data, pi + 1, ip_dlen);
+	memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
+	nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
+	nmsg->hdr.seq = htons(state.xmit_seq++);
+	memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
+	nmsg->ipdata.proto = pi->proto;
+	nmsg->ipdata.ip_dlen = htons(ip_dlen);
+	memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
 
-	/* Do encryption. */
-       out_data = crypt_buffer;
+       out_data = buffers->read_buffer;
 	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
-       local_to_netmsg(&nmsg, &out_data, &out_dlen);
+       if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
+        LOG("Encryption failed");
+        return 0;
+    }
 
 	(void)send(state.sockfd, out_data, out_dlen, 0);
 
@@ -176,52 +183,51 @@ return 0;
 }
 
 static void do_an_echo_request(void)
-{
-	char in_data[64], crypt_buffer[64];
-	struct minivtun_msg *nmsg = (void *)in_data;
-	void *out_msg;
-	size_t out_len;
-
-	memset(nmsg, 0x0, sizeof(nmsg->hdr) + sizeof(nmsg->echo));
-	nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_REQ;
-	nmsg->hdr.seq = htons(state.xmit_seq++);
-	memcpy(nmsg->hdr.auth_key, config.crypto_key, sizeof(nmsg->hdr.auth_key));
-	if (!config.tap_mode) {
-		nmsg->echo.loc_tun_in = config.tun_in_local;
+       char out_buffer[64];
+       struct minivtun_msg *nmsg = (struct minivtun_msg *)out_buffer;
+
+	memset(nmsg, 0x0, sizeof(nmsg->hdr) + sizeof(nmsg->echo));
+	nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_REQ;
+	nmsg->hdr.seq = htons(state.xmit_seq++);
+	memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
+	if (!config.tap_mode) {
+		nmsg->echo.loc_tun_in = config.tun_in_local;
 #if WITH_IPV6
-		nmsg->echo.loc_tun_in6 = config.tun_in6_local;
+               nmsg->echo.loc_tun_in6 = config.tun_in6_local;
 #endif
 	}
 	nmsg->echo.id = r;
 
-	out_msg = crypt_buffer;
-	out_len = sizeof(nmsg->hdr) + sizeof(nmsg->echo);
-	local_to_netmsg(nmsg, &out_msg, &out_len);
-
-	(void)send(state.sockfd, out_msg, out_len, 0);
+	if (local_to_netmsg(nmsg, &out_buffer, &out_len) != 0) {
+		LOG("Encryption failed");
+		return;
+	}
+
+	(void)send(state.sockfd, out_buffer, out_len, 0);
 
 	state.has_pending_echo = true;
-	state.pending_echo_id = r; /* must be checked on ECHO_ACK */
+       state.pending_echo_id = r;
 	state.stats_buckets[state.current_bucket].total_echo_sent++;
 }
 
 static void reset_state_on_reconnect(void)
-{
-	sstate.xmit_seq = (__u16)rand();
-	sstate.last_recv = __current;
-	sstate.last_echo_recv = __current;
-	sstate.last_echo_sent = (struct timeval) { 0, 0 }; /* trigger the first echo */
-	sstate.last_health_assess = __current;
-
-	/* Reset health assess variables */
-	sstate.has_pending_echo = false;
-	sstate.pending_echo_id = 0;
+	gettimeofday(&__current, NULL);
+
+	state.xmit_seq = (__u16)rand();
+	state.last_recv = __current;
+	state.last_echo_recv = __current;
+	state.last_echo_sent = (struct timeval) { 0, 0 };
+	state.last_health_assess = __current;
+
+	state.has_pending_echo = false;
+	state.pending_echo_id = 0;
 
 	/* Reset stats buckets */
 	for (unsigned i = 0; i < config.nr_stats_buckets; i++)
@@ -231,49 +237,45 @@ static bool do_link_health_assess(void)
 		rcvd += st->total_echo_rcvd;
 		rtt += st->total_rtt_ms;
 	}
-       /* Avoid generating negative values */
-       if (rcvd > sent)
-               rcvd = sent;
+       if (rcvd > sent) rcvd = sent;
 
 	drop_percent = sent ? ((sent - rcvd) * 100 / sent) : 0;
 	rtt_average = rcvd ? (rtt / rcvd) : 0;
 
-	/* Write into file */
 	if (config.health_file) {
 		FILE *fp;
 		remove(config.health_file);
 		if ((fp = fopen(config.health_file, "w"))) {
 			fprintf(fp, "Sent: %u, received: %u, drop: %u%%, RTT: %u\n",
-						sent, rcvd, drop_percent, rtt_average);
+				sent, rcvd, drop_percent, rtt_average);
 			fclose(fp);
 		}
 	} else {
-		printf("Sent: %u, received: %u, drop: %u%%, RTT: %u\n",
-				sent, rcvd, drop_percent, rtt_average);
+               LOG("Health - sent: %u, received: %u, drop: %u%%, RTT: %ums",
+				sent, rcvd, drop_percent, rtt_average);
 	}
 
-	/* Move to the next bucket and clear it */
 	state.current_bucket = (state.current_bucket + 1) % config.nr_stats_buckets;
 	zero_stats_data(&state.stats_buckets[state.current_bucket]);
 
 	if (!health_ok) {
-		syslog(LOG_INFO, "Unhealthy state - sent: %u, received: %u, drop: %u%%, RTT: %u",
-				sent, rcvd, drop_percent, rtt_average);
+               LOG("Unhealthy state - sent: %u, received: %u, drop: %u%%, RTT: %ums",
+				sent, rcvd, drop_percent, rtt_average);
 	}
 
 	return health_ok;
 }
 
 int run_client(const char *peer_addr_pair)
-{
-	char s_peer_addr[50];
-	struct timeval startup_time;
+       struct client_buffers buffers;
+
+	char s_peer_addr[50];
+	struct timeval startup_time;
+
+	buffers.size = MTU_TO_BUFFER_SIZE(config.tun_mtu);
+	buffers.read_buffer = malloc(buffers.size);
+	buffers.crypt_buffer = malloc(buffers.size);
+	buffers.tun_buffer = malloc(buffers.size);
+	if (!buffers.read_buffer || !buffers.crypt_buffer || !buffers.tun_buffer) {
+		PLOG("Failed to allocate client buffers");
+		exit(1);
+	}
 
-	/* Allocate statistics data buckets */
 	state.stats_buckets = malloc(sizeof(struct stats_data) * config.nr_stats_buckets);
 	assert(state.stats_buckets);
 
-	/* Remember the startup time for checking with 'config.exit_after' */
 	gettimeofday(&startup_time, NULL);
 
-	/* Dynamic link mode */
 	state.is_link_ok = false;
 	if (config.dynamic_link)
-		ip_link_set_updown(config.ifname, false);
+               plat_ip_link_set_updown(config.ifname, false);
 
-	/* Initial route metric */
 	state.rt_metric = config.vt_metric;
 
 	if (config.wait_dns) {
-		/* Connect later (state.sockfd < 0) */
 		state.sockfd = -1;
 		gettimeofday(&state.last_health_assess, NULL);
-		printf("Mini virtual tunneling client to '%s', interface: %s. \n",
-				peer_addr_pair, config.ifname);
+               LOG("Client to '%s', interface: %s.", peer_addr_pair, config.ifname);
 	} else if ((state.sockfd = resolve_and_connect(peer_addr_pair, &state.peer_addr)) >= 0) {
-		/* DNS resolve OK, start service normally */
 		reset_state_on_reconnect();
 		inet_ntop(state.peer_addr.sa.sa_family, addr_of_sockaddr(&state.peer_addr), 
 					s_peer_addr, sizeof(s_peer_addr));
-		printf("Mini virtual tunneling client to %s:%u, interface: %s.\n",
-				s_peer_addr, ntohs(port_of_sockaddr(&state.peer_addr)), config.ifname);
-	} else if (state.sockfd == -EINVAL) {
-		fprintf(stderr, "*** Invalid address pair '%s'.\n", peer_addr_pair);
-		return -1;
 	} else {
-		fprintf(stderr, "*** Unable to connect to '%s'.\n", peer_addr_pair);
+               LOG("*** Unable to resolve or connect to '%s'.", peer_addr_pair);
 		return -1;
 	}
 
 	if (config.exit_after)
-		printf("NOTICE: This client will exit autonomously in %u seconds.\n", config.exit_after);
-
-	/* Run in background */
-	if (config.in_background)
-		do_daemonize();
+		LOG("NOTICE: This client will exit autonomously in %u seconds.", config.exit_after);
 
 	if (config.pid_file) {
 		FILE *fp;
@@ -383,44 +381,32 @@ int run_client(const char *peer_addr_pair)
 		rc = select((state.tunfd > state.sockfd ? state.tunfd : state.sockfd) + 1,
 				&rset, NULL, NULL, &timeo);
 		if (rc < 0) {
-			if (errno == EINTR || errno == ERESTART) {
-				/* Fall through */
-			} else {
-				fprintf(stderr, "*** select(): %s.\n", strerror(errno));
-				return -1;
-			}
+                       if (errno == EINTR || errno == ERESTART) continue;
+                       PLOG("*** select() failed");
+                       return -1;
 		}
 
 		gettimeofday(&__current, NULL);
 
-		/* Date corruption check */
-		if (timercmp(&state.last_recv, &__current, >))
-			state.last_recv = __current;
-		if (timercmp(&state.last_echo_sent, &__current, >))
-			state.last_echo_sent = __current;
-		if (timercmp(&state.last_echo_recv, &__current, >))
-			state.last_echo_recv = __current;
-
-		/* Command line requires an "exit after N seconds" */
+		if (timercmp(&state.last_recv, &__current, >)) state.last_recv = __current;
+		if (timercmp(&state.last_echo_sent, &__current, >)) state.last_echo_sent = __current;
+		if (timercmp(&state.last_echo_recv, &__current, >)) state.last_echo_recv = __current;
+
 		if (config.exit_after && __sub_timeval_ms(&__current, &startup_time)
 				>= config.exit_after * 1000) {
-			syslog(LOG_INFO, "User sets a force-to-exit after %u seconds. Exited.",
-					config.exit_after);
+                       LOG("User sets a force-to-exit after %u seconds. Exited.", config.exit_after);
 			exit(0);
 		}
 
-		/* Check connection status or reconnect */
 		if (state.sockfd < 0 ||
 			(unsigned)__sub_timeval_ms(&__current, &state.last_echo_recv)
 				>= config.reconnect_timeo * 1000) {
 			need_reconnect = true;
 		} else {
-			/* Calculate packet loss and RTT for a link health assess */
 			if ((unsigned)__sub_timeval_ms(&__current, &state.last_health_assess)
 					>= config.health_assess_interval * 1000) {
 				state.last_health_assess = __current;
 				if (do_link_health_assess()) {
-					/* Call link-up scripts */
 					if (!state.is_link_ok) {
 						if (config.dynamic_link)
 							handle_link_up();
@@ -429,13 +415,11 @@ int run_client(const char *peer_addr_pair)
 					state.health_based_link_up = false;
 				} else {
 					need_reconnect = true;
-					/* Keep link down until next health assess passes */
 					state.health_based_link_up = true;
 				}
 			}
 		}
 
-		/* Rewind to initial route metric and trigger a reconnect */
 		if (rewind_dynamic_link_metric) {
 			rewind_dynamic_link_metric = false;
 			if (state.is_link_ok) {
@@ -444,44 +428,40 @@ int run_client(const char *peer_addr_pair)
 				state.is_link_ok = false;
 			}
 			state.rt_metric = config.vt_metric;
-			syslog(LOG_INFO, "Reset dynamic link route metric.");
+                       LOG("Reset dynamic link route metric.");
 			need_reconnect = true;
 		}
 
 		if (need_reconnect) {
 reconnect:
-			/* Call link-down scripts */
 			if (state.is_link_ok) {
 				if (config.dynamic_link)
 					handle_link_down();
 				state.is_link_ok = false;
 			}
-			/* Reopen socket for a different local port */
 			if (state.sockfd >= 0)
 				close(state.sockfd);
 			if ((state.sockfd = resolve_and_connect(peer_addr_pair, &state.peer_addr)) < 0) {
-				fprintf(stderr, "Unable to connect to '%s', retrying.\n", peer_addr_pair);
+                       LOG("Unable to connect to '%s', retrying.", peer_addr_pair);
 				sleep(5);
 				goto reconnect;
 			}
 			reset_state_on_reconnect();
 			inet_ntop(state.peer_addr.sa.sa_family, addr_of_sockaddr(&state.peer_addr), 
 							s_peer_addr, sizeof(s_peer_addr));
-			syslog(LOG_INFO, "Reconnected to %s:%u.", s_peer_addr,
-								ntohs(port_of_sockaddr(&state.peer_addr)));
+			LOG("Reconnected to %s:%u.", s_peer_addr,
+							ntohs(port_of_sockaddr(&state.peer_addr)));
 			continue;
 		}
 
 			if (state.sockfd >= 0 && FD_ISSET(state.sockfd, &rset)) {
-				rc = network_receiving();
+				network_receiving(&buffers);
 			}
 
 			if (FD_ISSET(state.tunfd, &rset)) {
-				rc = tunnel_receiving();
-				assert(rc == 0);
+				tunnel_receiving(&buffers);
 			}
 
-		/* Trigger an echo test */
 		if (state.sockfd >= 0 &&
 			(unsigned)__sub_timeval_ms(&__current, &state.last_echo_sent)
 				>= config.keepalive_interval * 1000) {
@@ -490,5 +470,12 @@ reconnect:
 		}
 	}
 
+       free(buffers.read_buffer);
+       free(buffers.crypt_buffer);
+       free(buffers.tun_buffer);
+	free(state.stats_buckets);
+
 	return 0;
 }
+
+#endif /* WITH_CLIENT_MODE */
diff --git a/src/crypto_openssl.c b/src/crypto_openssl.c
new file mode 100644
index 0000000..4fa89bf
--- /dev/null
+++ b/src/crypto_openssl.c
@@ -0,0 +1,190 @@
+/*
+ * Copyright (c) 2015 Justin Liu
+ * Author: Justin Liu <rssnsj@gmail.com>
+ *
+ * OpenSSL crypto backend
+ */
+
+#include <openssl/evp.h>
+#include <openssl/md5.h>
+#include <string.h>
+#include <assert.h>
+
+#include "crypto_wrapper.h"
+#include "log.h"
+
+
+struct name_cipher_pair {
+       const char *name;
+       const EVP_CIPHER *(*cipher)(void);
+};
+
+static struct name_cipher_pair cipher_pairs[] = {
+       { "aes-128", EVP_aes_128_cbc, },
+       { "aes-256", EVP_aes_256_cbc, },
+       { "des", EVP_des_cbc, },
+       { "desx", EVP_desx_cbc, },
+       { "rc4", EVP_rc4, },
+       { NULL, NULL, },
+};
+
+
+struct crypto_context {
+    const EVP_CIPHER *cptype;
+    unsigned char key[CRYPTO_MAX_KEY_SIZE];
+    size_t key_len;
+};
+
+
+const void * crypto_get_type(const char *name)
+{
+       const EVP_CIPHER *cipher = NULL;
+       int i;
+
+       for (i = 0; cipher_pairs[i].name; i++) {
+               if (strcasecmp(cipher_pairs[i].name, name) == 0) {
+                       cipher = cipher_pairs[i].cipher();
+                       break;
+               }
+       }
+
+       if (cipher) {
+               assert(EVP_CIPHER_key_length(cipher) <= CRYPTO_MAX_KEY_SIZE);
+               assert(EVP_CIPHER_iv_length(cipher) <= CRYPTO_MAX_BLOCK_SIZE);
+               return cipher;
+       } else {
+               return NULL;
+       }
+}
+
+
+static void fill_with_string_md5sum(const char *in, void *out, size_t outlen)
+{
+       char *outp = out, *oute = outp + outlen;
+       unsigned char md5_buf[16];
+    MD5_CTX ctx;
+
+       MD5_Init(&ctx);
+       MD5_Update(&ctx, in, strlen(in));
+       MD5_Final(md5_buf, &ctx);
+
+    memcpy(out, md5_buf, (outlen > 16) ? 16 : outlen);
+
+       /* Fill in remaining buffer with repeated data. */
+       for (outp = out + 16; outp < oute; outp += 16) {
+               size_t bs = (oute - outp >= 16) ? 16 : (oute - outp);
+               memcpy(outp, out, bs);
+       }
+}
+
+
+struct crypto_context* crypto_init(const void *cptype, const char* password)
+{
+    if (!cptype || !password || !password[0]) {
+        return NULL;
+    }
+
+    struct crypto_context* ctx = malloc(sizeof(struct crypto_context));
+    if (!ctx) {
+        PLOG("malloc failed for crypto context");
+        return NULL;
+    }
+
+    ctx->cptype = cptype;
+    ctx->key_len = EVP_CIPHER_key_length(ctx->cptype);
+    fill_with_string_md5sum(password, ctx->key, ctx->key_len);
+
+    return ctx;
+}
+
+
+void crypto_free(struct crypto_context* ctx)
+{
+    if (ctx) {
+        free(ctx);
+    }
+}
+
+static const char crypto_ivec_initdata[CRYPTO_MAX_BLOCK_SIZE] = {
+       0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
+       0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
+       0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
+       0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
+};
+
+#define CRYPTO_DATA_PADDING(data, dlen, bs) \
+       do { \
+               size_t last_len = *(dlen) % (bs); \
+               if (last_len) { \
+                       size_t padding_len = bs - last_len; \
+                       memset((char *)data + *(dlen), 0x0, padding_len); \
+                       *(dlen) += padding_len; \
+               } \
+       } while(0)
+
+int crypto_encrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
+{
+    if (!c_ctx) { // Encryption disabled
+        memmove(out, in, *dlen);
+        return 0;
+    }
+       size_t iv_len = EVP_CIPHER_iv_length(c_ctx->cptype);
+       EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
+       unsigned char iv[CRYPTO_MAX_KEY_SIZE];
+       int outl = 0, outl2 = 0;
+    int ret = -1;
+
+       if (iv_len == 0) iv_len = 16;
+
+       memcpy(iv, crypto_ivec_initdata, iv_len);
+       CRYPTO_DATA_PADDING(in, dlen, iv_len);
+
+       EVP_CIPHER_CTX_init(ctx);
+       if(!EVP_EncryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->key, iv)) goto out;
+       EVP_CIPHER_CTX_set_padding(ctx, 0);
+       if(!EVP_EncryptUpdate(ctx, out, &outl, in, *dlen)) goto out;
+       if(!EVP_EncryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2)) goto out;
+
+       *dlen = (size_t)(outl + outl2);
+    ret = 0;
+
out:
+       EVP_CIPHER_CTX_cleanup(ctx);
+       EVP_CIPHER_CTX_free(ctx);
+    return ret;
+}
+int crypto_decrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
+{
+    if (!c_ctx) { // Encryption disabled
+        memmove(out, in, *dlen);
+        return 0;
+    }
+
+       size_t iv_len = EVP_CIPHER_iv_length(c_ctx->cptype);
+       EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
+       unsigned char iv[CRYPTO_MAX_KEY_SIZE];
+       int outl = 0, outl2 = 0;
+    int ret = -1;
+
+       if (iv_len == 0) iv_len = 16;
+
+       memcpy(iv, crypto_ivec_initdata, iv_len);
+       CRYPTO_DATA_PADDING(in, dlen, iv_len);
+
+       EVP_CIPHER_CTX_init(ctx);
+       if(!EVP_DecryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->key, iv)) goto out;
+       EVP_CIPHER_CTX_set_padding(ctx, 0);
+       if(!EVP_DecryptUpdate(ctx, out, &outl, in, *dlen)) goto out;
+       if(!EVP_DecryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2)) goto out;
+
+       *dlen = (size_t)(outl + outl2);
+    ret = 0;
+
out:
+       EVP_CIPHER_CTX_cleanup(ctx);
+       EVP_CIPHER_CTX_free(ctx);
+    return ret;
+}
diff --git a/src/crypto_wrapper.h b/src/crypto_wrapper.h
new file mode 100644
index 0000000..a7661ef
--- /dev/null
+++ b/src/crypto_wrapper.h
@@ -0,0 +1,28 @@
+/*
+ * Copyright (c) 2015 Justin Liu
+ * Author: Justin Liu <rssnsj@gmail.com>
+ *
+ * Crypto wrapper interface
+ */
+#ifndef __CRYPTO_WRAPPER_H
+#define __CRYPTO_WRAPPER_H
+
+#include <stddef.h>
+
+#define CRYPTO_MAX_KEY_SIZE  32
+#define CRYPTO_MAX_BLOCK_SIZE  32
+
+struct crypto_context;
+
+const void * crypto_get_type(const char *name);
+
+struct crypto_context* crypto_init(const void *cptype, const char* password);
+
+void crypto_free(struct crypto_context* ctx);
+
+int crypto_encrypt(struct crypto_context* ctx, void* in, void* out, size_t* len);
+
+int crypto_decrypt(struct crypto_context* ctx, void* in, void* out, size_t* len);
+
+
+#endif /* __CRYPTO_WRAPPER_H */
diff --git a/src/log.h b/src/log.h
new file mode 100644
index 0000000..7f2ac8c
--- /dev/null
+++ b/src/log.h
@@ -0,0 +1,24 @@
+/*
+ * Copyright (c) 2015 Justin Liu
+ * Author: Justin Liu <rssnsj@gmail.com>
+ *
+ * logging abstraction
+ */
+
+#ifndef __MINIVTUN_LOG_H
+#define __MINIVTUN_LOG_H
+
+#include <stdio.h>
+#include <string.h>
+#include <errno.h>
+
+#ifdef NO_LOG
+    #define LOG(...) do {} while(0)
+    #define PLOG(...) do {} while(0)
+#else
+    #define LOG(fmt, ...) fprintf(stderr, "minivtun: " fmt "\n", ##__VA_ARGS__)
+    #define PLOG(fmt, ...) fprintf(stderr, "minivtun: " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))
+#endif
+
+#endif /* __MINIVTUN_LOG_H */
+
diff --git a/src/minivtun.c b/src/minivtun.c
index 6e88304..ad03d28 100644
--- a/src/minivtun.c
+++ b/src/minivtun.c
@@ -17,16 +17,18 @@
 #include <sys/ioctl.h>
 
 #include "minivtun.h"
+#include "list.h"
 
 struct minivtun_config config = {
        .ifname = "",
        .tun_mtu = 1300,
-       .tun_qlen = 1500, /* driver default: 500 */
+       .tun_qlen = 500, /* driver default */
+       .crypto_algo = "aes-128",
        .crypto_passwd = "",
-       .crypto_type = NULL,
        .pid_file = NULL,
        .in_background = false,
        .tap_mode = false,
+#if WITH_CLIENT_MODE
        .wait_dns = false,
        .exit_after = 0,
        .dynamic_link = false,
@@ -40,31 +42,41 @@ struct minivtun_config config = {
        .vt_metric = 0,
        .metric_stepping = 0,
        .vt_table = "",
+#endif
 };
 
 struct state_variables state = {
        .tunfd = -1,
        .sockfd = -1,
+       .crypto_ctx = NULL,
 };
 
 static void vt_route_add(short af, void *n, int prefix, void *g)
-{
+       union {
+               struct in_addr in;
+#if WITH_IPV6
+               struct in6_addr in6;
+#endif
+       } *network = n, *gateway = g;
        struct vt_route *rt;
 
        rt = malloc(sizeof(struct vt_route));
+    if (!rt) {
+        PLOG("malloc for vt_route failed");
+        return;
+    }
        memset(rt, 0x0, sizeof(*rt));
 
        rt->af = af;
        rt->prefix = prefix;
        if (af == AF_INET) {
                rt->network.in = network->in;
-               rt->network.in.s_addr &= prefix ? htonl(~((1 << (32 - prefix)) - 1)) : 0;
+               rt->network.in.s_addr &= prefix ? htonl(~((1U << (32 - prefix)) - 1)) : 0;
                rt->gateway.in = gateway->in;
-       } else if (af == AF_INET6) {
+       }
+#if WITH_IPV6
+    else if (af == AF_INET6) {
                int i;
                rt->network.in6 = network->in6;
                if (prefix < 128) {
@@ -73,7 +85,9 @@ static void vt_route_add(short af, void *n, int prefix, void *g)
                                rt->network.in6.s6_addr[i] &= 0x00;
                }
                rt->gateway.in6 = gateway->in6;
-       } else {
+       }
+#endif
+    else {
                assert(0);
        }
 
@@ -89,7 +103,9 @@ static void parse_virtual_route(const char *arg)
        int prefix = -1;
        union {
                struct in_addr in;
+#if WITH_IPV6
                struct in6_addr in6;
+#endif
        } network, gateway;
 
        strncpy(expr, arg, sizeof(expr));
@@ -106,27 +122,31 @@ static void parse_virtual_route(const char *arg)
                prefix = strtol(pfx, NULL, 10);
                if (errno != ERANGE && prefix >= 0 && prefix <= 32 &&
                        inet_pton(AF_INET, net, &network)) {
-                       /* 192.168.0.0/16=10.7.7.1 */
                        af = AF_INET;
-               } else if (errno != ERANGE && prefix >= 0 && prefix <= 128 &&
+               }
+#if WITH_IPV6
+        else if (errno != ERANGE && prefix >= 0 && prefix <= 128 &&
                        inet_pton(AF_INET6, net, &network)) {
-                       /* 2001:470:f9f2:ffff::/64=2001:470:f9f2::1 */
                        af = AF_INET6;
-               } else {
-                       fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
+               }
+#endif
+        else {
+                       LOG("*** Not a valid route expression '%s'.", arg);
                        exit(1);
                }
        } else {
                if (inet_pton(AF_INET, net, &network)) {
-                       /* 192.168.0.1=10.7.7.1 */
                        af = AF_INET;
                        prefix = 32;
-               } else if (inet_pton(AF_INET6, net, &network)) {
-                       /* 2001:470:f9f2:ffff::1=2001:470:f9f2::1 */
+               }
+#if WITH_IPV6
+        else if (inet_pton(AF_INET6, net, &network)) {
                        af = AF_INET6;
                        prefix = 128;
-               } else {
-                       fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
+               }
+#endif
+        else {
+                       LOG("*** Not a valid route expression '%s'.", arg);
                        exit(1);
                }
        }
@@ -134,7 +154,7 @@ static void parse_virtual_route(const char *arg)
        /* Has gateway or not */
        if (gw) {
                if (!inet_pton(af, gw, &gateway)) {
-                       fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
+                       LOG("*** Not a valid route expression '%s'.", arg);
                        exit(1);
                }
        } else {
@@ -146,69 +166,82 @@ static void parse_virtual_route(const char *arg)
 
 static void print_help(int argc, char *argv[])
-{
-       int i;
-
        printf("Mini virtual tunneller in non-standard protocol.\n");
        printf("Usage:\n");
        printf("  %s [options]\n", argv[0]);
        printf("Options:\n");
+#if WITH_SERVER_MODE
        printf("  -l, --local <ip:port>               local IP:port for server to listen\n");
+#endif
+#if WITH_CLIENT_MODE
        printf("  -r, --remote <host:port>            host:port of server to connect (brace with [] for bare IPv6)\n");
+#endif
        printf("  -n, --ifname <ifname>               virtual interface name\n");
        printf("  -m, --mtu <mtu>                     set MTU size, default: %u.\n", config.tun_mtu);
        printf("  -Q, --qlen <qlen>                   set TX queue length, default: %u\n", config.tun_qlen);
-       printf("  -a, --ipv4-addr <tun_lip/tun_rip>   pointopoint IPv4 pair of the virtual interface\n");
-       printf("                  <tun_lip/pfx_len>   IPv4 address/prefix length pair\n");
-       printf("  -A, --ipv6-addr <tun_ip6/pfx_len>   IPv6 address/prefix length pair\n");
+       printf("  -a, --ipv4-addr <tun_lip/pfx>   IPv4 address/prefix length pair\n");
+#if WITH_IPV6
+       printf("  -A, --ipv6-addr <tun_ip6/pfx>   IPv6 address/prefix length pair\n");
+#endif
+#if WITH_DAEMONIZE
        printf("  -d, --daemon                        run as daemon process\n");
        printf("  -p, --pidfile <pid_file>            PID file of the daemon\n");
+#endif
        printf("  -E, --tap                           TAP mode (L2, ethernet)\n");
        printf("  -e, --key <encryption_key>          shared password for data encryption\n");
-       printf("  -t, --type <encryption_type>        encryption type\n");
-       printf("  -v, --route <network/prefix>[=gw]   attached IPv4/IPv6 route on this link, can be multiple\n");
+       printf("  -t, --algo <cipher>                 encryption algorithm (default: %s)\n", config.crypto_algo);
+       printf("  -v, --route <net/pfx>[=gw]          attached route on this link, can be multiple\n");
+#if WITH_CLIENT_MODE
        printf("  -w, --wait-dns                      wait for DNS resolve ready after service started\n");
        printf("  -D, --dynamic-link                  dynamic link mode, not bring up until data received\n");
-       printf("  -M, --metric <metric>[++stepping]   metric of attached IPv4 routes\n");
+       printf("  -M, --metric <metric>[++step]     metric of attached IPv4 routes\n");
        printf("  -T, --table <table_name>            route table of the attached IPv4 routes\n");
        printf("  -x, --exit-after <N>                force the client to exit after N seconds\n");
        printf("  -H, --health-file <file_path>       file for writing real-time health data\n");
        printf("  -R, --reconnect-timeo <N>           maximum inactive time (seconds) before reconnect, default: %u\n", config.reconnect_timeo);
        printf("  -K, --keepalive <N>                 seconds between keep-alive tests, default: %u\n", config.keepalive_interval);
        printf("  -S, --health-assess <N>             seconds between health assess, default: %u\n", config.health_assess_interval);
        printf("  -B, --stats-buckets <N>             health data buckets, default: %u\n", config.nr_stats_buckets);
        printf("  -P, --max-droprate <1~100>          maximum allowed packet drop percentage, default: %u%%\n", config.max_droprate);
        printf("  -X, --max-rtt <N>                   maximum allowed echo delay (ms), default: unlimited\n");
+#endif
        printf("  -h, --help                          print this help\n");
-       printf("Supported encryption algorithms:\n");
-       printf("  ");
-       for (i = 0; cipher_pairs[i].name; i++)
-               printf("%s, ", cipher_pairs[i].name);
-       printf("\n");
 }
 
 int main(int argc, char *argv[])
-{
-       const char *tun_ip_config = NULL, *tun_ip6_config = NULL;
+       const char *tun_ip_config = NULL;
+#if WITH_IPV6
+    const char *tun_ip6_config = NULL;
+#endif
        const char *loc_addr_pair = NULL, *peer_addr_pair = NULL;
-       const char *crypto_type = CRYPTO_DEFAULT_ALGORITHM;
        int override_mtu = 0, opt;
        struct timeval current;
        char *sp;
 
        static struct option long_opts[] = {
+#if WITH_SERVER_MODE
                { "local", required_argument, 0, 'l', },
+#endif
+#if WITH_CLIENT_MODE
                { "remote", required_argument, 0, 'r', },
+#endif
                { "ipv4-addr", required_argument, 0, 'a', },
+#if WITH_IPV6
                { "ipv6-addr", required_argument, 0, 'A', },
+#endif
                { "ifname", required_argument, 0, 'n', },
                { "mtu", required_argument, 0, 'm', },
                { "qlen", required_argument, 0, 'Q', },
+#if WITH_DAEMONIZE
                { "pidfile", required_argument, 0, 'p', },
                { "daemon", no_argument, 0, 'd', },
+#endif
                { "tap", no_argument, 0, 'E', },
                { "key", required_argument, 0, 'e', },
-               { "type", required_argument, 0, 't', },
+               { "algo", required_argument, 0, 't', },
                { "route", required_argument, 0, 'v', },
+#if WITH_CLIENT_MODE
                { "wait-dns", no_argument, 0, 'w', },
                { "exit-after", required_argument, 0, 'x', },
                { "dynamic-link", no_argument, 0, 'D', },
@@ -221,25 +254,32 @@ int main(int argc, char *argv[])
                { "max-rtt", required_argument, 0, 'X', },
                { "metric", required_argument, 0, 'M', },
                { "table", required_argument, 0, 'T', },
+#endif
                { "help", no_argument, 0, 'h', },
                { 0, 0, 0, 0, },
        };
 
-       while ((opt = getopt_long(argc, argv, "r:l:a:A:m:Q:n:p:e:t:v:x:R:K:S:B:H:P:X:M:T:DEdwh",
+       while ((opt = getopt_long(argc, argv, "l:r:a:A:m:Q:n:p:e:t:v:x:R:K:S:B:H:P:X:M:T:DEwdh",
                        long_opts, NULL)) != -1) {
                switch (opt) {
+#if WITH_SERVER_MODE
                case 'l':
                        loc_addr_pair = optarg;
                        break;
+#endif
+#if WITH_CLIENT_MODE
                case 'r':
                        peer_addr_pair = optarg;
                        break;
+#endif
                case 'a':
                        tun_ip_config = optarg;
                        break;
+#if WITH_IPV6
                case 'A':
                        tun_ip6_config = optarg;
                        break;
+#endif
                case 'n':
                        strncpy(config.ifname, optarg, sizeof(config.ifname) - 1);
                        config.ifname[sizeof(config.ifname) - 1] = '\0';
@@ -250,12 +290,14 @@ int main(int argc, char *argv[])
                case 'Q':
                        config.tun_qlen = strtoul(optarg, NULL, 10);
                        break;
+#if WITH_DAEMONIZE
                case 'p':
                        config.pid_file = optarg;
                        break;
                case 'd':
                        config.in_background = true;
                        break;
+#endif
                case 'E':
                        config.tap_mode = true;
                        break;
                case 'e':
                        config.crypto_passwd = optarg;
                        break;
                case 't':
-                       crypto_type = optarg;
+                       config.crypto_algo = optarg;
                        break;
                case 'v':
                        parse_virtual_route(optarg);
                        break;
+#if WITH_CLIENT_MODE
                case 'w':
                        config.wait_dns = true;
                        break;
@@ -295,7 +337,7 @@ int main(int argc, char *argv[])
                case 'P':
                        config.max_droprate = strtoul(optarg, NULL, 10);
                        if (config.max_droprate < 1 || config.max_droprate > 100) {
-                               fprintf(stderr, "*** Acceptable '--max-droprate' values: 1~100.\n");
+                               LOG("*** Acceptable '--max-droprate' values: 1~100.");
                                exit(1);
                        }
                        break;
@@ -311,54 +353,68 @@ int main(int argc, char *argv[])
                        strncpy(config.vt_table, optarg, sizeof(config.vt_table));
                        config.vt_table[sizeof(config.vt_table) - 1] = '\0';
                        break;
+#endif
                case 'h':
                        print_help(argc, argv);
                        exit(0);
                        break;
                case '?':
                        exit(1);
                }
        }
 
        if (override_mtu) {
                config.tun_mtu = override_mtu;
-       } else {
-               /* Default ethernet mode MTU: 1500 */
-               if (config.tap_mode)
+       } else if (config.tap_mode) {
                        config.tun_mtu = 1500;
        }
 
-       /* Random seed */
        gettimeofday(&current, NULL);
        srand(current.tv_sec ^ current.tv_usec ^ getpid());
 
        if (config.ifname[0] == '\0')
                strcpy(config.ifname, "mv%d");
-       if ((state.tunfd = tun_alloc(config.ifname, config.tap_mode)) < 0) {
-               fprintf(stderr, "*** open_tun() failed: %s.\n", strerror(errno));
+       if ((state.tunfd = plat_tun_alloc(config.ifname, config.tap_mode)) < 0) {
+               LOG("*** plat_tun_alloc() failed: %s.", strerror(errno));
                exit(1);
        }
 
        openlog(config.ifname, LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_USER);
 
-       /* Configure IPv4 address for the interface. */
        if (tun_ip_config) {
                char s_lip[20], s_rip[20], *sp;
                struct in_addr vaddr;
                int pfxlen = 0;
 
                if (!(sp = strchr(tun_ip_config, '/'))) {
-                       fprintf(stderr, "*** Invalid IPv4 address pair: %s.\n", tun_ip_config);
+                       LOG("*** Invalid IPv4 address pair: %s.", tun_ip_config);
                        exit(1);
                }
                strncpy(s_lip, tun_ip_config, sp - tun_ip_config);
                s_lip[sp - tun_ip_config] = '\0';
                sp++;
                strncpy(s_rip, sp, sizeof(s_rip));
                s_rip[sizeof(s_rip) - 1] = '\0';
 
                if (!inet_pton(AF_INET, s_lip, &vaddr)) {
-                       fprintf(stderr, "*** Invalid local IPv4 address: %s.\n", s_lip);
+                       LOG("*** Invalid local IPv4 address: %s.", s_lip);
                        exit(1);
                }
                config.tun_in_local = vaddr;
                if (inet_pton(AF_INET, s_rip, &vaddr)) {
+#if WITH_SERVER_MODE
+                    /* This is server mode specific, so the client does not
+                     * need to add a route for the peer. */
+                    if (loc_addr_pair) {
+                                struct in_addr nz = { .s_addr = 0 };
+                                vt_route_add(AF_INET, &nz, 0, &vaddr);
+                    }
+#else
+                    /* If client only, then `loc_addr_pair` should be NULL */
+                    if (loc_addr_pair) {
+                        LOG("*** Internal error: loc_addr_pair should be NULL in client-only build.");
+                        exit(1);
+                    }
+#endif
+
                        if (loc_addr_pair) {
                                struct in_addr nz = { .s_addr = 0 };
                                vt_route_add(AF_INET, &nz, 0, &vaddr);
@@ -332,24 +388,24 @@ int main(int argc, char *argv[])
                                config.tun_in_peer = vaddr;
                } else if (sscanf(s_rip, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen < 31 ) {
                        config.tun_in_prefix = pfxlen;
-               } else {
-                       fprintf(stderr, "*** Not a legal netmask or prefix length: %s.\n", s_rip);
+               } else {
+                       LOG("*** Not a legal netmask or prefix length: %s.", s_rip);
                        exit(1);
                }
-               ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
-                               &config.tun_in_peer, config.tun_in_prefix);
+               plat_ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
+                               &config.tun_in_peer, config.tun_in_prefix);
        }
 
-       /* Configure IPv6 address if set. */
-       if (tun_ip6_config) {
-               char s_lip[50], s_pfx[20], *sp;
-               struct in6_addr vaddr;
-               int pfxlen = 0;
-
-               if (!(sp = strchr(tun_ip6_config, '/'))) {
-                       fprintf(stderr, "*** Invalid IPv6 address pair: %s.\n", tun_ip6_config);
-                       exit(1);
-               }
-               strncpy(s_lip, tun_ip6_config, sp - tun_ip6_config);
-               s_lip[sp - tun_ip6_config] = '\0';
-               sp++;
-               strncpy(s_pfx, sp, sizeof(s_pfx));
-               s_pfx[sizeof(s_pfx) - 1] = '\0';
-
-               if (!inet_pton(AF_INET6, s_lip, &vaddr)) {
-                       fprintf(stderr, "*** Invalid local IPv6 address: %s.\n", s_lip);
-                       exit(1);
-               }
-               config.tun_in6_local = vaddr;
-               if (!(sscanf(s_pfx, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen <= 128)) {
-                       fprintf(stderr, "*** Not a legal prefix length: %s.\n", s_pfx);
-                       exit(1);
-               }
-               config.tun_in6_prefix = pfxlen;
-
-               ip_addr_add_ipv6(config.ifname, &config.tun_in6_local, config.tun_in6_prefix);
+       }
+
+#if WITH_IPV6
+       if (tun_ip6_config) {
+               char s_lip[50], s_pfx[20], *sp;
+               struct in6_addr vaddr;
+               int pfxlen = 0;
+
+               if (!(sp = strchr(tun_ip6_config, '/'))) {
+                       LOG("*** Invalid IPv6 address pair: %s.", tun_ip6_config);
+                       exit(1);
+               }
+               strncpy(s_lip, tun_ip6_config, sp - tun_ip6_config);
+               s_lip[sp - tun_ip6_config] = '\0';
+               sp++;
+               strncpy(s_pfx, sp, sizeof(s_pfx));
+               s_pfx[sizeof(s_pfx) - 1] = '\0';
+
+               if (!inet_pton(AF_INET6, s_lip, &vaddr)) {
+                       LOG("*** Invalid local IPv6 address: %s.", s_lip);
+                       exit(1);
+               }
+               config.tun_in6_local = vaddr;
+               if (!(sscanf(s_pfx, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen <= 128)) {
+                       LOG("*** Not a legal prefix length: %s.", s_pfx);
+                       exit(1);
+               }
+               config.tun_in6_prefix = pfxlen;
+
+               plat_ip_addr_add_ipv6(config.ifname, &config.tun_in6_local, config.tun_in6_prefix);
+       }
+#endif
+
+       plat_ip_link_set_mtu(config.ifname, config.tun_mtu);
+       plat_ip_link_set_txqueue_len(config.ifname, config.tun_qlen);
+       plat_ip_link_set_updown(config.ifname, true);
+
+       if (enabled_encryption()) {
+               const void* cptype = crypto_get_type(config.crypto_algo);
+               if (cptype == NULL) {
+                       LOG("*** No such encryption type defined: %s.", config.crypto_algo);
+                       exit(1);
+               }
+               state.crypto_ctx = crypto_init(cptype, config.crypto_passwd);
+               if (state.crypto_ctx == NULL) {
+                       LOG("*** Failed to initialize crypto context.");
+                       exit(1);
+               }
+       } else {
+               LOG("*** WARNING: Transmission will not be encrypted.");
+       }
+
+#if WITH_DAEMONIZE
+    if(config.in_background) {
+        plat_daemonize();
+    }
+#endif
+
+#if WITH_SERVER_MODE
+        if (loc_addr_pair) {
+                run_server(loc_addr_pair);
+       } else
+#endif
+#if WITH_CLIENT_MODE
+    if (peer_addr_pair) {
+                run_client(peer_addr_pair);
+       } else
+#endif
+    {
+               LOG("*** No valid local or peer address specified.");
+               exit(1);
+       }
+
+       /* Some cleanups before exit */
+#if WITH_CLIENT_MODE
+        if (config.health_file)
+                remove(config.health_file);
+#endif
+    crypto_free(state.crypto_ctx);
+       closelog();
+
+       return 0;
+}
+diff --git a/src/minivtun.h b/src/minivtun.h
index cdbddd8..e000b7e 100644
--- a/src/minivtun.h
+++ b/src/minivtun.h
@@ -8,6 +8,8 @@
 #define __MINIVTUN_H
 
 #include "library.h"
+#include "platform.h"
+#include "crypto_wrapper.h"
 
 extern struct minivtun_config config;
 extern struct state_variables state;
@@ -21,7 +23,9 @@ struct vt_route {
        short af;
        union {
                struct in_addr in;
+#if WITH_IPV6
                struct in6_addr in6;
+#endif
                struct mac_addr mac;
        } network, gateway;
        int prefix;
@@ -30,26 +34,27 @@ struct minivtun_config {
        char ifname[40];
        unsigned tun_mtu;
        unsigned tun_qlen;
+       const char *crypto_algo;
        const char *crypto_passwd;
        const char *pid_file;
        bool in_background;
        bool tap_mode;
 
-       char crypto_key[CRYPTO_MAX_KEY_SIZE];
-       const void *crypto_type;
-
        /* IPv4 address settings */
        struct in_addr tun_in_local;
        struct in_addr tun_in_peer;
        int tun_in_prefix;
 
+#if WITH_IPV6
        /* IPv6 address settings */
        struct in6_addr tun_in6_local;
        int tun_in6_prefix;
+#endif
 
        /* Dynamic routes for client, or virtual routes for server */
        struct vt_route *vt_routes;
 
+#if WITH_CLIENT_MODE
        /* Client only configuration */
        bool wait_dns;
        unsigned exit_after;
@@ -64,6 +69,7 @@ struct minivtun_config {
        unsigned vt_metric;
        int metric_stepping; /* dynamic link route metric stepping factor */
        char vt_table[32];
+#endif
 };
 
 /* Statistics data for health assess */
@@ -84,7 +90,9 @@ static inline void zero_stats_data(struct stats_data *st)
 struct state_variables {
        int tunfd;
        int sockfd;
+       struct crypto_context *crypto_ctx;
 
+#if WITH_CLIENT_MODE
        /* *** Client specific *** */
        struct sockaddr_inx peer_addr;
        __u16 xmit_seq;
@@ -101,10 +109,13 @@ struct state_variables {
        __be32 pending_echo_id;
        struct stats_buckets *stats_buckets;
        unsigned current_bucket;
+#endif
+
+#if WITH_SERVER_MODE
        /* *** Server specific *** */
        struct sockaddr_inx local_addr;
        struct timeval last_walk;
+#endif
 };
 
 enum {
@@ -114,7 +125,8 @@ enum {
        MINIVTUN_MSG_ECHO_ACK,
 };
 
-#define NM_PI_BUFFER_SIZE  (1024 * 8)
+// Make buffer size dynamic based on MTU, allowing for IP headers and crypto overhead
+#define MTU_TO_BUFFER_SIZE(mtu) (mtu + 512)
 
 struct minivtun_msg {
        struct {
@@ -128,13 +140,15 @@ struct minivtun_msg {
                struct {
                        __be16 proto;   /* ETH_P_IP or ETH_P_IPV6 */
                        __be16 ip_dlen; /* Total length of IP/IPv6 data */
-                       char data[NM_PI_BUFFER_SIZE];
-               } __attribute__((packed)) ipdata;    /* 4+ */
+                       char data[];    // Flexible array member
+               } __attribute__((packed)) ipdata;
                struct {
                        union {
                                struct {
                                        struct in_addr loc_tun_in;
+#if WITH_IPV6
                                        struct in6_addr loc_tun_in6;
+#endif
                                };
                                struct mac_addr loc_tun_mac;
                        };
@@ -146,27 +160,23 @@ struct minivtun_msg {
 #define MINIVTUN_MSG_BASIC_HLEN  (sizeof(((struct minivtun_msg *)0)->hdr))
 #define MINIVTUN_MSG_IPDATA_OFFSET  (offsetof(struct minivtun_msg, ipdata.data))
 
-#define enabled_encryption()  (config.crypto_passwd[0])
+#define enabled_encryption()  (config.crypto_passwd && config.crypto_passwd[0])
 
-static inline void local_to_netmsg(void *in, void **out, size_t *dlen)
+static inline int local_to_netmsg(void *in, void **out, size_t *dlen)
 {
-       if (enabled_encryption()) {
-               datagram_encrypt(config.crypto_key, config.crypto_type, in, *out, dlen);
-       } else {
-               *out = in;
-       }
+       return crypto_encrypt(state.crypto_ctx, in, *out, dlen);
 }
 static inline int netmsg_to_local(void *in, void **out, size_t *dlen)
-{
-       if (enabled_encryption()) {
-               datagram_decrypt(config.crypto_key, config.crypto_type, in, *out, dlen);
-       } else {
-               *out = in;
-       }
+       return crypto_decrypt(state.crypto_ctx, in, *out, dlen);
 }
 
+#if WITH_CLIENT_MODE
 int run_client(const char *peer_addr_pair);
+#endif
+#if WITH_SERVER_MODE
 int run_server(const char *loc_addr_pair);
+#endif
 
 #endif /* __MINIVTUN_H */
 
diff --git a/src/platform.h b/src/platform.h
new file mode 100644
index 0000000..c6d9ced
--- /dev/null
+++ b/src/platform.h
@@ -0,0 +1,33 @@
+/*
+ * Copyright (c) 2015 Justin Liu
+ * Author: Justin Liu <rssnsj@gmail.com>
+ *
+ * Platform-specific network functions
+ */
+
+#ifndef __PLATFORM_H
+#define __PLATFORM_H
+
+#include "library.h"
+
+int plat_tun_alloc(char *dev, bool tap_mode);
+
+void plat_ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
+               struct in_addr *peer, int prefix);
+
+#ifdef WITH_IPV6
+void plat_ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix);
+#endif
+
+void plat_ip_link_set_mtu(const char *ifname, unsigned mtu);
+void plat_ip_link_set_txqueue_len(const char *ifname, unsigned qlen);
+void plat_ip_link_set_updown(const char *ifname, bool up);
+
+void plat_ip_route_add(int af, const char *ifname, void *network, int prefix,
+               int metric, const char *table);
+
+#ifdef WITH_DAEMONIZE
+void plat_daemonize(void);
+#endif
+
+#endif /* __PLATFORM_H */
diff --git a/src/platform_bsd.c b/src/platform_bsd.c
new file mode 100644
index 0000000..56a893e
--- /dev/null
+++ b/src/platform_bsd.c
@@ -0,0 +1,243 @@
+/*
+ * Copyright (c) 2015 Justin Liu
+ * Author: Justin Liu <rssnsj@gmail.com>
+ *
+ * BSD/macOS platform-specific functions
+ */
+
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+#include <errno.h>
+#include <sys/socket.h>
+#include <sys/ioctl.h>
+#include <net/if.h>
+#include <net/route.h>
+
+#include "log.h"
+#include "platform.h"
+
+/* Protocol info prepended to the packets */
+struct tun_pi {
+    __u16  flags;
+    __be16 proto;
+};
+#define TUNSIFHEAD  _IOW('t', 96, int)
+#define TUNGIFHEAD  _IOR('t', 97, int)
+
+int plat_tun_alloc(char *dev, bool tap_mode)
+{
+    // Note: BSD/macOS does not have a clear separation between tun and tap
+    // in the same way Linux does. The device name 'tun' is used.
+       int fd = -1, i;
+    char dev_path[20];
+
+       for (i = 0; i < 16; i++) {
+               sprintf(dev_path, "/dev/tun%d", i);
+               if ((fd = open(dev_path, O_RDWR)) >= 0) {
+                       sprintf(dev, "tun%d", i);
+                       return fd;
+               }
+       }
+
+    PLOG("Failed to open any /dev/tunX device");
+       return -1;
+}
+
+/* Like strncpy but make sure the resulting string is always 0 terminated. */
+static char *safe_strncpy(char *dst, const char *src, size_t size)
+{
+       dst[size - 1] = '\0';
+       return strncpy(dst, src, size - 1);
+}
+
+static int __set_flag(int sockfd, const char *ifname, short flag)
+{
+       struct ifreq ifr;
+
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCGIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       ifr.ifr_flags |= flag;
+       if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCSIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       return 0;
+}
+
+static int __clr_flag(int sockfd, const char *ifname, short flag)
+{
+       struct ifreq ifr;
+
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCGIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       ifr.ifr_flags &= ~flag;
+       if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCSIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       return 0;
+}
+
+static int __set_ip_using(int sockfd, const char *name, int c,
+               const struct in_addr *addr)
+{
+       struct sockaddr_in sin;
+       struct ifreq ifr;
+
+       safe_strncpy(ifr.ifr_name, name, IFNAMSIZ);
+       memset(&sin, 0, sizeof(struct sockaddr));
+       sin.sin_family = AF_INET;
+       sin.sin_addr = *addr;
+       memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
+       if (ioctl(sockfd, c, &ifr) < 0)
+               return -1;
+       return 0;
+}
+
+void plat_ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
+               struct in_addr *peer, int prefix)
+{
+       char cmd[256];
+    char local_str[INET_ADDRSTRLEN];
+    char peer_str[INET_ADDRSTRLEN];
+
+    inet_ntop(AF_INET, local, local_str, sizeof(local_str));
+
+    if (is_valid_unicast_in(local) && is_valid_unicast_in(peer)) {
+        inet_ntop(AF_INET, peer, peer_str, sizeof(peer_str));
+        sprintf(cmd, "ifconfig %s %s %s up", ifname, local_str, peer_str);
+    } else if (is_valid_unicast_in(local) && prefix > 0) {
+        sprintf(cmd, "ifconfig %s %s/%d up", ifname, local_str, prefix);
+    } else {
+        return;
+    }
+
+    LOG("executing: %s", cmd);
+    if(system(cmd) != 0) {
+        LOG("Command failed: %s", cmd);
+    }
+}
+
+
+#ifdef WITH_IPV6
+void plat_ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix)
+{
+    char cmd[256];
+    char local_str[INET6_ADDRSTRLEN];
+
+    if (!is_valid_unicast_in6(local) || prefix <= 0) {
+        return;
+    }
+
+    inet_ntop(AF_INET6, local, local_str, sizeof(local_str));
+    sprintf(cmd, "ifconfig %s inet6 %s prefixlen %d up", ifname, local_str, prefix);
+
+    LOG("executing: %s", cmd);
+    if(system(cmd) != 0) {
+        LOG("Command failed: %s", cmd);
+    }
+}
+#endif
+
+void plat_ip_link_set_mtu(const char *ifname, unsigned mtu)
+{
+    char cmd[256];
+    sprintf(cmd, "ifconfig %s mtu %u", ifname, mtu);
+    LOG("executing: %s", cmd);
+    if(system(cmd) != 0) {
+        LOG("Command failed: %s", cmd);
+    }
+}
+
+// This is a Linux-specific feature
+void plat_ip_link_set_txqueue_len(const char *ifname, unsigned qlen) {
+    (void)ifname;
+    (void)qlen;
+    // Not supported on BSD/macOS
+}
+
+void plat_ip_link_set_updown(const char *ifname, bool up)
+{
+       int sockfd;
+
+       if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
+               PLOG("socket() failed");
+               return;
+    }
+       if (up) {
+               __set_flag(sockfd, ifname, IFF_UP | IFF_RUNNING);
+       } else {
+               __clr_flag(sockfd, ifname, IFF_UP);
+       }
+       close(sockfd);
+}
+
+void plat_ip_route_add(int af, const char *ifname, void *network, int prefix,
+               int metric, const char *table)
+{
+    // NOTE: This uses system() which is inefficient.
+    // A proper implementation would use ioctl(SIOCADDRT) with struct rt_msghdr
+    // but this is significantly more complex than the Linux version.
+    // For now, we isolate the inefficient call here.
+       char cmd[256], __net[64] = "";
+       inet_ntop(af, network, __net, sizeof(__net));
+
+    if (table) {
+        LOG("Routing tables are not supported on BSD/macOS via this function");
+        return;
+    }
+
+       sprintf(cmd, "route add -net %s/%d -interface %s",
+                   __net, prefix, ifname);
+
+    LOG("executing: %s", cmd);
+    if(system(cmd) != 0) {
+        LOG("Command failed: %s", cmd);
+    }
+}
+
+#ifdef WITH_DAEMONIZE
+void plat_daemonize(void)
+{
+       pid_t pid;
+       if ((pid = fork()) < 0) {
+               PLOG("fork() failed");
+               exit(1);
+       }
+       if (pid > 0) {
+               exit(0);
+       }
+
+       if (setsid() < 0) {
+        PLOG("setsid() failed");
+               exit(1);
+    }
+
+       if ((pid = fork()) < 0) {
+               PLOG("fork() failed");
+               exit(1);
+       }
+       if (pid > 0) {
+               exit(0);
+       }
+
+    if (chdir("/tmp") < 0) {
+        PLOG("chdir(/tmp) failed");
+    }
+
+       freopen("/dev/null", "r", stdin);
+       freopen("/dev/null", "w", stdout);
+       freopen("/dev/null", "w", stderr);
+}
+#endif
diff --git a/src/platform_linux.c b/src/platform_linux.c
new file mode 100644
index 0000000..51a2458
--- /dev/null
+++ b/src/platform_linux.c
@@ -0,0 +1,350 @@
+/*
+ * Copyright (c) 2015 Justin Liu
+ * Author: Justin Liu <rssnsj@gmail.com>
+ *
+ * Linux platform-specific functions
+ */
+
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+#include <errno.h>
+#include <sys/socket.h>
+#include <sys/ioctl.h>
+#include <net/if.h>
+#include <net/route.h>
+#include <linux/if_tun.h>
+
+#include "log.h"
+#include "platform.h"
+
+int plat_tun_alloc(char *dev, bool tap_mode)
+{
+       struct ifreq ifr;
+       int fd, err;
+
+       if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
+        PLOG("Failed to open /dev/net/tun");
+               return -1;
+    }
+
+       memset(&ifr, 0, sizeof(ifr));
+       ifr.ifr_flags = tap_mode ? IFF_TAP : IFF_TUN;
+    ifr.ifr_flags |= IFF_NO_PI; // We provide protocol info manually
+
+       if (dev && *dev)
+               strncpy(ifr.ifr_name, dev, IFNAMSIZ);
+
+       if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
+        PLOG("ioctl(TUNSETIFF) failed");
+               close(fd);
+               return err;
+       }
+       strcpy(dev, ifr.ifr_name);
+       return fd;
+}
+
+/* Like strncpy but make sure the resulting string is always 0 terminated. */
+static char *safe_strncpy(char *dst, const char *src, size_t size)
+{
+       dst[size - 1] = '\0';
+       return strncpy(dst, src, size - 1);
+}
+
+static int __get_ifindex(const char *ifname)
+{
+       struct ifreq ifr;
+       int sockfd;
+
+       if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
+               return -1;
+       memset(&ifr, 0x0, sizeof(ifr));
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       if (ioctl(sockfd, SIOGIFINDEX, &ifr) < 0) {
+               close(sockfd);
+               return -1;
+       }
+       close(sockfd);
+       return ifr.ifr_ifindex;
+}
+
+static int __set_flag(int sockfd, const char *ifname, short flag)
+{
+       struct ifreq ifr;
+
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCGIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       ifr.ifr_flags |= flag;
+       if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCSIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       return 0;
+}
+
+static int __clr_flag(int sockfd, const char *ifname, short flag)
+{
+       struct ifreq ifr;
+
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCGIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       ifr.ifr_flags &= ~flag;
+       if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
+               PLOG("ioctl(SIOCSIFFLAGS) failed for %s", ifname);
+               return -1;
+       }
+       return 0;
+}
+
+static int __set_ip_using(int sockfd, const char *name, int c,
+               const struct in_addr *addr)
+{
+       struct sockaddr_in sin;
+       struct ifreq ifr;
+
+       safe_strncpy(ifr.ifr_name, name, IFNAMSIZ);
+       memset(&sin, 0, sizeof(struct sockaddr));
+       sin.sin_family = AF_INET;
+       sin.sin_addr = *addr;
+       memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
+       if (ioctl(sockfd, c, &ifr) < 0)
+               return -1;
+       return 0;
+}
+
+
+void plat_ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
+               struct in_addr *peer, int prefix)
+{
+       int sockfd;
+
+       if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
+        PLOG("socket() failed");
+               return;
+    }
+
+       if (is_valid_unicast_in(local) && is_valid_unicast_in(peer)) {
+               __set_ip_using(sockfd, ifname, SIOCSIFADDR, local);
+               __set_ip_using(sockfd, ifname, SIOCSIFDSTADDR, peer);
+               __set_flag(sockfd, ifname, IFF_POINTOPOINT | IFF_UP | IFF_RUNNING);
+       } else if (is_valid_unicast_in(local) && prefix > 0) {
+               struct in_addr mask;
+               mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));
+               __set_ip_using(sockfd, ifname, SIOCSIFADDR, local);
+               __set_ip_using(sockfd, ifname, SIOCSIFNETMASK, &mask);
+               __set_flag(sockfd, ifname, IFF_UP | IFF_RUNNING);
+       }
+       close(sockfd);
+}
+
+#ifdef WITH_IPV6
+void plat_ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix)
+{
+       struct in6_ifreq {
+               struct in6_addr ifr6_addr;
+               __u32 ifr6_prefixlen;
+               unsigned int ifr6_ifindex;
+       };
+       struct in6_ifreq ifr6;
+       int sockfd, ifindex;
+
+       if ((ifindex = __get_ifindex(ifname)) < 0) {
+               PLOG("SIOGIFINDEX failed for %s", ifname);
+               return;
+       }
+       if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
+        PLOG("socket(AF_INET6) failed");
+               return;
+    }
+       if (is_valid_unicast_in6(local) && prefix > 0) {
+               memcpy(&ifr6.ifr6_addr, local, sizeof(*local));
+               ifr6.ifr6_ifindex = ifindex;
+               ifr6.ifr6_prefixlen = prefix;
+               if (ioctl(sockfd, SIOCSIFADDR, &ifr6) < 0)
+                       PLOG("ioctl(SIOCSIFADDR) for IPv6 failed");
+       }
+       close(sockfd);
+}
+#endif
+
+void plat_ip_link_set_mtu(const char *ifname, unsigned mtu)
+{
+       struct ifreq ifr;
+       int sockfd;
+
+       if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
+         PLOG("socket() failed");
+               return;
+    }
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       ifr.ifr_mtu = mtu;
+       if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0)
+               PLOG("ioctl(SIOCSIFMTU) to %u failed", mtu);
+       close(sockfd);
+}
+
+void plat_ip_link_set_txqueue_len(const char *ifname, unsigned qlen)
+{
+       struct ifreq ifr;
+       int sockfd;
+
+       if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
+        PLOG("socket() failed");
+               return;
+    }
+       safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
+       ifr.ifr_qlen = qlen;
+       if (ioctl(sockfd, SIOCSIFTXQLEN, &ifr) < 0)
+               PLOG("ioctl(SIOCSIFTXQLEN) failed");
+       close(sockfd);
+}
+
+void plat_ip_link_set_updown(const char *ifname, bool up)
+{
+       int sockfd;
+
+       if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
+        PLOG("socket() failed");
+               return;
+    }
+       if (up) {
+               __set_flag(sockfd, ifname, IFF_UP | IFF_RUNNING);
+       } else {
+               __clr_flag(sockfd, ifname, IFF_UP);
+       }
+       close(sockfd);
+}
+
+
+void plat_ip_route_add(int af, const char *ifname, void *network, int prefix,
+               int metric, const char *table)
+{
+       if (table) {
+               char cmd[256], __net[64] = "";
+               inet_ntop(af, network, __net, sizeof(__net));
+               sprintf(cmd, "ip %s route add %s/%d dev %s metric %d table %s",
+                       af == AF_INET6 ? "-6" : "", __net, prefix, ifname, metric, table);
+               if (system(cmd) != 0) {
+            LOG("system('%s') failed", cmd);
+        }
+        return;
+       }
+
+#ifdef WITH_IPV6
+       if (af == AF_INET6) {
+               struct in6_rtmsg {
+                       struct in6_addr rtmsg_dst;
+                       __u16 rtmsg_dst_len;
+                       __u16 rtmsg_flags;
+                       __u32 rtmsg_metric;
+                       int rtmsg_ifindex;
+               } rt6;
+               int sockfd, ifindex;
+
+               if ((ifindex = __get_ifindex(ifname)) < 0) {
+                       PLOG("SIOGIFINDEX failed for %s", ifname);
+                       return;
+               }
+
+               memset(&rt6, 0x0, sizeof(rt6));
+               memcpy(&rt6.rtmsg_dst, network, sizeof(struct in6_addr));
+               rt6.rtmsg_flags = RTF_UP;
+               if (prefix == 128)
+                       rt6.rtmsg_flags |= RTF_HOST;
+               rt6.rtmsg_metric = metric;
+               rt6.rtmsg_dst_len = prefix;
+               rt6.rtmsg_ifindex = ifindex;
+
+               if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
+                       PLOG("socket(AF_INET6) failed");
+                       return;
+               }
+               if(ioctl(sockfd, SIOCADDRT, &rt6) < 0) {
+            PLOG("ioctl(SIOCADDRT) for IPv6 failed");
+        }
+               close(sockfd);
+        return;
+       }
+#endif
+
+       if (af == AF_INET) {
+               struct rtentry rt;
+               int sockfd;
+
+               memset(&rt, 0x0, sizeof(rt));
+               rt.rt_flags = RTF_UP;
+               if (prefix == 32)
+                       rt.rt_flags |= RTF_HOST;
+               ((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
+               ((struct sockaddr_in *)&rt.rt_dst)->sin_addr = *(struct in_addr *)network;
+               ((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
+               ((struct sockaddr_in *)&rt.rt_genmask)->sin_addr.s_addr =
+                               prefix ? htonl(~((1 << (32 - prefix)) - 1)) : 0;
+               rt.rt_metric = metric + 1; /* +1 for binary compatibility! */
+               rt.rt_dev = (char *)ifname;
+               if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
+                       PLOG("socket() failed");
+                       return;
+               }
+               if(ioctl(sockfd, SIOCADDRT, &rt) < 0) {
+            PLOG("ioctl(SIOCADDRT) for IPv4 failed");
+        }
+               close(sockfd);
+       }
+}
+
+
+#ifdef WITH_DAEMONIZE
+void plat_daemonize(void)
+{
+       pid_t pid;
+       int fd;
+
+       if ((pid = fork()) < 0) {
+               PLOG("fork() failed");
+               exit(1);
+       }
+       if (pid > 0) {
+               exit(0);
+       }
+
+       if (setsid() < 0) {
+        PLOG("setsid() failed");
+               exit(1);
+    }
+
+       signal(SIGHUP, SIG_IGN);
+
+       if ((pid = fork()) < 0) {
+               PLOG("fork() failed");
+               exit(1);
+       }
+       if (pid > 0) {
+               exit(0);
+       }
+
+       umask(0);
+    chdir("/");
+
+       for (fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
+               close(fd);
+       }
+
+    fd = open("/dev/null", O_RDWR);
+    if (fd >= 0) {
+        dup2(fd, STDIN_FILENO);
+        dup2(fd, STDOUT_FILENO);
+        dup2(fd, STDERR_FILENO);
+        if (fd > 2) close(fd);
+    }
+}
+#endif
diff --git a/src/server.c b/src/server.c
index f85e03f..8d5bd4d 100644
--- a/src/server.c
+++ b/src/server.c
@@ -4,6 +4,8 @@
  * https://github.com/rssnsj/minivtun
  */
 
+#if WITH_SERVER_MODE
+
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -22,11 +24,20 @@
 
 static __u32 hash_initval = 0;
 
+struct server_buffers {
+    size_t size;
+    char *read_buffer;
+    char *crypt_buffer;
+    char *tun_buffer;
+};
+
 static void *vt_route_lookup(short af, const void *a)
-{
+       const union {
+               struct in_addr in;
+#if WITH_IPV6
+               struct in6_addr in6;
+#endif
+       } *addr = a;
        struct vt_route *rt;
 
        rt = malloc(sizeof(struct vt_route));
@@ -37,11 +48,13 @@ static void *vt_route_lookup(short af, const void *a)
                        if (rt->prefix == 0) {
                                return &rt->gateway.in;
                        } else {
-                               in_addr_t m = rt->prefix ? htonl(~((1 << (32 - rt->prefix)) - 1)) : 0;
+                               in_addr_t m = rt->prefix ? htonl(~((1U << (32 - rt->prefix)) - 1)) : 0;
                                if ((addr->in.s_addr & m) == rt->network.in.s_addr)
                                        return &rt->gateway.in;
                        }
-               } else if (af == AF_INET6) {
+               }
+#if WITH_IPV6
+        else if (af == AF_INET6) {
                        if (rt->prefix == 0) {
                                return &rt->gateway.in6;
                        } else if (rt->prefix < 128) {
@@ -55,6 +68,7 @@ static void *vt_route_lookup(short af, const void *a)
                                }
 
                        }
+               }
+#endif
        }
 
        return NULL;
@@ -70,7 +84,6 @@ struct ra_entry {
        int refs;
 };
 
-/* Hash table for dedicated clients (real addresses). */
 #define RA_SET_HASH_SIZE  (1 << 3)
 #define RA_SET_LIMIT_EACH_WALK  (10)
 static struct list_head ra_set_hbase[RA_SET_HASH_SIZE];
@@ -78,10 +91,13 @@ static unsigned ra_set_len;
 
 static inline __u32 real_addr_hash(const struct sockaddr_inx *sa)
-{
+       if (sa->sa.sa_family == AF_INET6) {
+               return jhash_2words(sa->sa.sa_family, sa->in6.sin6_port, jhash2((__u32 *)&sa->in6.sin6_addr, 4, hash_initval));
+       } else {
+               return jhash_3words(sa->sa.sa_family, sa->in.sin_port, sa->in.sin_addr.s_addr, hash_initval);
+       }
+#if WITH_IPV6
        if (sa->sa.sa_family == AF_INET6) {
                return jhash_2words(sa->sa.sa_family, sa->in6.sin6_port,
                        jhash2((__u32 *)&sa->in6.sin6_addr, 4, hash_initval));
-       } else {
+       } else {
                return jhash_3words(sa->sa.sa_family, sa->in.sin_port,
                        sa->in.sin_addr.s_addr, hash_initval);
        }
+#endif
 }
 
 static inline int real_addr_comp(
@@ -99,7 +115,7 @@ static struct ra_entry *ra_get_or_create(const struct sockaddr_inx *sa)
        }
 
        if ((re = malloc(sizeof(*re))) == NULL) {
-               syslog(LOG_ERR, "*** [%s] malloc(): %s.", __FUNCTION__, strerror(errno));
+               PLOG("malloc for ra_entry failed");
                return NULL;
        }
 
@@ -111,8 +127,8 @@ static struct ra_entry *ra_get_or_create(const struct sockaddr_inx *sa)
 
        inet_ntop(re->real_addr.sa.sa_family, addr_of_sockaddr(&re->real_addr),
                        s_real_addr, sizeof(s_real_addr));
-       syslog(LOG_INFO, "New client [%s:%u]", s_real_addr,
-                       port_of_sockaddr(&re->real_addr));
+       LOG("New client [%s:%u]", s_real_addr,
+                       ntohs(port_of_sockaddr(&re->real_addr)));
 
        return re;
 }
@@ -133,7 +149,7 @@ static inline void ra_entry_release(struct ra_entry *re)
 
        inet_ntop(re->real_addr.sa.sa_family, addr_of_sockaddr(&re->real_addr),
                        s_real_addr, sizeof(s_real_addr));
-       syslog(LOG_INFO, "Recycled client [%s:%u]", s_real_addr,
+       LOG("Recycled client [%s:%u]", s_real_addr,
                        ntohs(port_of_sockaddr(&re->real_addr)));
 
        free(re);
@@ -143,7 +159,9 @@ struct tun_addr {
        unsigned short af;
        union {
                struct in_addr in;
+#if WITH_IPV6
                struct in6_addr in6;
+#endif
                struct mac_addr mac;
        };
 };
@@ -154,7 +172,6 @@ struct tun_client {
        struct timeval last_recv;
 };
 
-/* Hash table of virtual address in tunnel. */
 #define VA_MAP_HASH_SIZE  (1 << 4)
 #define VA_MAP_LIMIT_EACH_WALK  (10)
 static struct list_head va_map_hbase[VA_MAP_HASH_SIZE];
@@ -177,11 +194,15 @@ static inline __u32 tun_addr_hash(const struct tun_addr *addr)
 {
        if (addr->af == AF_INET) {
                return jhash_2words(addr->af, addr->in.s_addr, hash_initval);
-       } else if (addr->af == AF_INET6) {
+       }
+#if WITH_IPV6
+    else if (addr->af == AF_INET6) {
                const __be32 *a = (void *)&addr->in6;
                return jhash_2words(a[2], a[3],
                        jhash_3words(addr->af, a[0], a[1], hash_initval));
-       } else if (addr->af == AF_MACADDR) {
+       }
+#endif
+    else if (addr->af == AF_MACADDR) {
                const __be32 *a = (void *)&addr->mac;
                const __be16 *b = (void *)(a + 1);
                return jhash_3words(addr->af, *a, *b, hash_initval);
@@ -194,27 +215,18 @@ static inline __u32 tun_addr_hash(const struct tun_addr *addr)
 static inline int tun_addr_comp(
                const struct tun_addr *a1, const struct tun_addr *a2)
-{
-       if (a1->af != a2->af)
-               return 1;
+       if (a1->af != a2->af) return 1;
 
        if (a1->af == AF_INET) {
-               if (a1->in.s_addr == a2->in.s_addr) {
-                       return 0;
-               } else {
-                       return 1;
-               }
-       } else if (a1->af == AF_INET6) {
-               if (is_in6_equal(&a1->in6, &a2->in6)) {
-                       return 0;
-               } else {
-                       return 1;
-               }
-       } else if (a1->af == AF_MACADDR) {
-               if (is_mac_equal(&a1->mac, &a2->mac)) {
-                       return 0;
-               } else {
-                       return 1;
-               }
+               return (a1->in.s_addr == a2->in.s_addr) ? 0 : 1;
+       }
+#if WITH_IPV6
+    else if (a1->af == AF_INET6) {
+               return is_in6_equal(&a1->in6, &a2->in6) ? 0 : 1;
+       }
+#endif
+    else if (a1->af == AF_MACADDR) {
+               return is_mac_equal(&a1->mac, &a2->mac) ? 0 : 1;
        } else {
                abort();
                return 0;
@@ -227,9 +239,11 @@ static void tun_addr_ntop(const struct tun_addr *a, char *buf, socklen_t bufsz)
 
        switch (a->af) {
        case AF_INET:
+#if WITH_IPV6
        case AF_INET6:
+#endif
                inet_ntop(a->af, &a->in, buf, bufsz);
                break;
        default:
@@ -237,20 +251,6 @@ static void tun_addr_ntop(const struct tun_addr *a, char *buf, socklen_t bufsz)
        }
 }
 
-#ifdef DUMP_TUN_CLIENTS_ON_WALK
-static inline void tun_client_dump(struct tun_client *ce)
-{
-       char s_virt_addr[50] = "", s_real_addr[50] = "";
-
-       tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
-       inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
-                         s_real_addr, sizeof(s_real_addr));
-       printf("[%s] (%s:%u), last_recv: %lu\n", s_virt_addr,
-                       s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)),
-                       (unsigned long)ce->last_recv.tv_sec);
-}
-#endif
-
 static inline void tun_client_release(struct tun_client *ce)
-{
        char s_virt_addr[50], s_real_addr[50];
@@ -258,7 +258,7 @@ static inline void tun_client_release(struct tun_client *ce)
        tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
        inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
                        s_real_addr, sizeof(s_real_addr));
-       syslog(LOG_INFO, "Recycled virtual address [%s] at [%s:%u].", s_virt_addr,
+       LOG("Recycled virtual address [%s] at [%s:%u].", s_virt_addr,
                        s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)));
 
        ra_put_no_free(ce->ra);
@@ -293,7 +293,6 @@ static struct tun_client *tun_client_get_or_create(
        list_for_each_entry_safe (ce, __ce, chain, list) {
                if (tun_addr_comp(&ce->virt_addr, vaddr) == 0) {
                        if (!is_sockaddr_equal(&ce->ra->real_addr, raddr)) {
-                               /* Real address changed, reassign a new entry for it. */
                                ra_put_no_free(ce->ra);
                                if ((ce->ra = ra_get_or_create(raddr)) == NULL) {
                                        tun_client_release(ce);
@@ -304,15 +303,13 @@ static struct tun_client *tun_client_get_or_create(
                }
        }
 
-       /* Not found, always create new entry. */
        if ((ce = malloc(sizeof(*ce))) == NULL) {
-               syslog(LOG_ERR, "*** [%s] malloc(): %s.", __FUNCTION__, strerror(errno));
+               PLOG("malloc for tun_client failed");
                return NULL;
        }
 
        ce->virt_addr = *vaddr;
 
-       /* Get real_addr entry before adding to list. */
        if ((ce->ra = ra_get_or_create(raddr)) == NULL) {
                free(ce);
                return NULL;
@@ -323,13 +320,12 @@ static struct tun_client *tun_client_get_or_create(
        tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
        inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
                        s_real_addr, sizeof(s_real_addr));
-       syslog(LOG_INFO, "New virtual address [%s] at [%s:%u].", s_virt_addr,
+       LOG("New virtual address [%s] at [%s:%u].", s_virt_addr,
                        s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)));
 
        return ce;
 }
 
-/* Send echo reply back to a client */
 static void reply_an_echo_ack(struct minivtun_msg *req, struct ra_entry *re)
-{
-       char in_data[64], crypt_buffer[64];
-       struct minivtun_msg *nmsg = (void *)in_data;
-       void *out_msg;
-       size_t out_len;
-
-       memset(nmsg, 0x0, sizeof(nmsg->hdr) + sizeof(nmsg->echo));
-       nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_ACK;
-       nmsg->hdr.seq = htons(re->xmit_seq++);
-       memcpy(nmsg->hdr.auth_key, config.crypto_key, sizeof(nmsg->hdr.auth_key));
-       nmsg->echo = req->echo;
-
-       out_msg = crypt_buffer;
-       out_len = sizeof(nmsg->hdr) + sizeof(nmsg->echo);
-       local_to_netmsg(nmsg, &out_msg, &out_len);
-
-       (void)sendto(state.sockfd, out_msg, out_len, 0,
-                       (struct sockaddr *)&re->real_addr, sizeof_sockaddr(&re->real_addr));
+       char out_buffer[64];
+       struct minivtun_msg *nmsg = (struct minivtun_msg *)out_buffer;
+
+	memset(nmsg, 0x0, sizeof(nmsg->hdr) + sizeof(nmsg->echo));
+	nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_ACK;
+	nmsg->hdr.seq = htons(re->xmit_seq++);
+	memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
+	nmsg->echo = req->echo;
+
+	if (local_to_netmsg(nmsg, &out_buffer, &out_len) != 0) {
+		LOG("Encryption failed");
+		return;
+	}
+
+	(void)sendto(state.sockfd, out_buffer, out_len, 0,
+				(struct sockaddr *)&re->real_addr, sizeof_sockaddr(&re->real_addr));
 }
 
 static void va_ra_walk_continue(void)
@@ -364,18 +360,12 @@ static void va_ra_walk_continue(void)
 
        gettimeofday(&__current, NULL);
 
-       if (va_walk_max > va_map_len)
-               va_walk_max = va_map_len;
-       if (ra_walk_max > ra_set_len)
-               ra_walk_max = ra_set_len;
+       if (va_walk_max > va_map_len) va_walk_max = va_map_len;
+       if (ra_walk_max > ra_set_len) ra_walk_max = ra_set_len;
 
-       /* Recycle timeout virtual address entries. */
        if (va_walk_max > 0) {
                do {
                        list_for_each_entry_safe (ce, __ce, &va_map_hbase[va_index], list) {
-#ifdef DUMP_TUN_CLIENTS_ON_WALK
-                               tun_client_dump(ce);
-#endif
                                if (__sub_timeval_ms(&__current, &ce->last_recv) >
                                        config.reconnect_timeo * 1000) {
                                        tun_client_release(ce);
@@ -386,7 +376,6 @@ static void va_ra_walk_continue(void)
                } while (va_count < va_walk_max && va_index != __va_index);
        }
 
-       /* Recycle or keep-alive real client addresses. */
        if (ra_walk_max > 0) {
                do {
                        list_for_each_entry_safe (re, __re, &ra_set_hbase[ra_index], list) {
@@ -402,7 +391,7 @@ static void va_ra_walk_continue(void)
                } while (ra_count < ra_walk_max && ra_index != __ra_index);
        }
 
-       printf("Online clients: %u, addresses: %u\n", ra_set_len, va_map_len);
+       LOG("Online clients: %u, addresses: %u", ra_set_len, va_map_len);
 }
 
 static inline void source_addr_of_ipdata(
@@ -413,9 +402,11 @@ static inline void source_addr_of_ipdata(
        case AF_INET:
                memcpy(&addr->in, (char *)data + 12, 4);
                break;
+#if WITH_IPV6
        case AF_INET6:
                memcpy(&addr->in6, (char *)data + 8, 16);
                break;
+#endif
        case AF_MACADDR:
                memcpy(&addr->mac, (char *)data + 6, 6);
                break;
@@ -432,9 +423,11 @@ static inline void dest_addr_of_ipdata(
        case AF_INET:
                memcpy(&addr->in, (char *)data + 16, 4);
                break;
+#if WITH_IPV6
        case AF_INET6:
                memcpy(&addr->in6, (char *)data + 24, 16);
                break;
+#endif
        case AF_MACADDR:
                memcpy(&addr->mac, (char *)data + 0, 6);
                break;
@@ -444,11 +437,9 @@ static inline void dest_addr_of_ipdata(
 }
 
 
-static int network_receiving(void)
+static int network_receiving(struct server_buffers* buffers)
-{
-       char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
        struct minivtun_msg *nmsg;
-       struct tun_pi pi;
        void *out_data;
        size_t ip_dlen, out_dlen;
        unsigned short af = 0;
@@ -458,44 +449,43 @@ static int network_receiving(void)
        struct sockaddr_inx real_peer;
        socklen_t real_peer_alen;
        struct iovec iov[2];
+    char pi_buf[sizeof(struct tun_pi)];
+    struct tun_pi* pi = (struct tun_pi*)pi_buf;
        struct timeval __current;
        int rc;
 
        gettimeofday(&__current, NULL);
 
        real_peer_alen = sizeof(real_peer);
-       rc = recvfrom(state.sockfd, &read_buffer, NM_PI_BUFFER_SIZE, 0,
+       rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0,
                        (struct sockaddr *)&real_peer, &real_peer_alen);
        if (rc <= 0)
                return -1;
 
-       out_data = crypt_buffer;
+       out_data = buffers->crypt_buffer;
        out_dlen = (size_t)rc;
-       netmsg_to_local(read_buffer, &out_data, &out_dlen);
+       if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
+        LOG("Decryption failed");
+        return 0;
+    }
        nmsg = out_data;
 
        if (out_dlen < MINIVTUN_MSG_BASIC_HLEN)
                return 0;
 
-       /* Verify password. */
-       if (memcmp(nmsg->hdr.auth_key, config.crypto_key,
-               sizeof(nmsg->hdr.auth_key)) != 0)
+       if (memcmp(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key)) != 0)
                return 0;
 
        switch (nmsg->hdr.opcode) {
        case MINIVTUN_MSG_ECHO_REQ:
-               /* Keep the real address alive */
                if ((re = ra_get_or_create(&real_peer))) {
                        re->last_recv = __current;
-                       /* Send echo reply */
                        reply_an_echo_ack(nmsg, re);
                        ra_put_no_free(re);
                }
                if (out_dlen < MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo))
                        return 0;
-               /* Keep virtual addresses alive */
                if (config.tap_mode) {
-                       /* TAP mode, handle as MAC address */
                        if (is_valid_unicast_mac(&nmsg->echo.loc_tun_mac)) {
                                virt_addr.af = AF_MACADDR;
                                virt_addr.mac = nmsg->echo.loc_tun_mac;
@@ -506,45 +496,44 @@ static int network_receiving(void)
                                        ce->last_recv = __current;
                        }
                } else {
-                       /* TUN mode, handle as IP/IPv6 addresses */
                        if (is_valid_unicast_in(&nmsg->echo.loc_tun_in)) {
                                virt_addr.af = AF_INET;
                                virt_addr.in = nmsg->echo.loc_tun_in;
                                if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
                                        ce->last_recv = __current;
                        }
+#if WITH_IPV6
                        if (is_valid_unicast_in6(&nmsg->echo.loc_tun_in6)) {
                                virt_addr.af = AF_INET6;
                                virt_addr.in6 = nmsg->echo.loc_tun_in6;
                                if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
                                        ce->last_recv = __current;
                        }
+#endif
                }
                break;
        case MINIVTUN_MSG_IPDATA:
                if (config.tap_mode) {
                        af = AF_MACADDR;
-                       /* No ethernet packet is shorter than 14 bytes. */
-                       if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 14)
-                               return 0;
+                       if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 14) return 0;
                        nmsg->ipdata.proto = 0;
                        ip_dlen = out_dlen - MINIVTUN_MSG_IPDATA_OFFSET;
                } else {
                        if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
                                af = AF_INET;
-                               /* No valid IP packet is shorter than 20 bytes. */
-                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20)
-                                       return 0;
-                       } else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
+                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20) return 0;
+                       }
+#if WITH_IPV6
+            else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
                                af = AF_INET6;
-                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 40)
-                                       return 0;
-                       } else {
-                               syslog(LOG_WARNING, "*** Invalid protocol: 0x%x.", ntohs(nmsg->ipdata.proto));
+                               if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 40) return 0;
+                       }
+#endif
+            else {
+                               LOG("*** Invalid protocol: 0x%x.", ntohs(nmsg->ipdata.proto));
                                return 0;
                        }
                        ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
-                       /* Drop incomplete IP packets. */
                        if (out_dlen - MINIVTUN_MSG_IPDATA_OFFSET < ip_dlen)
                                return 0;
                }
@@ -670,11 +659,10 @@ static int network_receiving(void)
        return 0;
 }
 
-static int tunnel_receiving(void)
+static int tunnel_receiving(struct server_buffers* buffers)
-{
-       char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
-       struct tun_pi *pi = (void *)read_buffer;
-       struct minivtun_msg nmsg;
+       struct minivtun_msg *nmsg = (struct minivtun_msg *)buffers->crypt_buffer;
+       struct tun_pi *pi = (struct tun_pi *)buffers->tun_buffer;
        void *out_data;
        size_t ip_dlen, out_dlen;
        unsigned short af = 0;
@@ -682,31 +670,28 @@ static int tunnel_receiving(void)
        struct tun_client *ce;
        int rc;
 
-       rc = read(state.tunfd, pi, NM_PI_BUFFER_SIZE);
-       if (rc < sizeof(struct tun_pi))
-               return -1;
-
-       osx_af_to_ether(&pi->proto);
+       rc = read(state.tunfd, pi, buffers->size);
+       if (rc <= 0) return -1;
+       if ((size_t)rc < sizeof(struct tun_pi)) return -1;
 
        ip_dlen = (size_t)rc - sizeof(struct tun_pi);
 
        if (config.tap_mode) {
-               /* Ethernet frame */
                af = AF_MACADDR;
-               if (ip_dlen < 14)
-                       return 0;
+               if (ip_dlen < 14) return 0;
        } else {
-               /* We only accept IPv4 or IPv6 frames. */
                if (pi->proto == htons(ETH_P_IP)) {
                        af = AF_INET;
-                       if (ip_dlen < 20)
-                               return 0;
-               } else if (pi->proto == htons(ETH_P_IPV6)) {
+                       if (ip_dlen < 20) return 0;
+               }
+#if WITH_IPV6
+        else if (pi->proto == htons(ETH_P_IPV6)) {
                        af = AF_INET6;
-                       if (ip_dlen < 40)
-                               return 0;
-               } else {
-                       syslog(LOG_WARNING, "*** Invalid protocol: 0x%x.", ntohs(pi->proto));
+                       if (ip_dlen < 40) return 0;
+               }
+#endif
+        else {
+                       LOG("*** Invalid protocol from tun: 0x%x.", ntohs(pi->proto));
                        return 0;
                }
        }
 
        dest_addr_of_ipdata(pi + 1, af, &virt_addr);
 
        if ((ce = tun_client_try_get(&virt_addr)) == NULL) {
-               /**
-                * Not an existing client address, lookup the pseudo
-                * route table for a destination to send.
-                *//* Looku
+               void *gw;
+               if ((gw = vt_route_lookup(virt_addr.af, &virt_addr.in))) {
+                       struct tun_addr __va;
+                       memset(&__va, 0x0, sizeof(__va));
+                       __va.af = virt_addr.af;
+                       if (virt_addr.af == AF_INET) {
+                               __va.in = *(struct in_addr *)gw;
+                       }
+#if WITH_IPV6
+            else if (virt_addr.af == AF_INET6) {
+                               __va.in6 = *(struct in6_addr *)gw;
+                       }
+#endif
+            else {
+                               __va.mac = *(struct mac_addr *)gw;
+                       }
+                       if ((ce = tun_client_try_get(&__va)) == NULL)
+                               return 0;
+
+                       if ((ce = tun_client_get_or_create(&virt_addr,
+                               &ce->ra->real_addr)) == NULL)
+                               return 0;
+               } else if (config.tap_mode) {
+            // In tap mode, broadcast to all clients if dest is unknown
+            ce = NULL;
+               } else {
+                       return 0;
+               }
+       }
+
+       memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
+       nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
+       memcpy(nmsg->hdr.auth_key, state.crypto_ctx, sizeof(nmsg->hdr.auth_key));
+       nmsg->ipdata.proto = pi->proto;
+       nmsg->ipdata.ip_dlen = htons(ip_dlen);
+       memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
+
+       out_data = buffers->read_buffer;
+       out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
+       if(local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
+        LOG("Encryption failed");
+        return 0;
+    }
+
+       if (ce) {
+               nmsg->hdr.seq = htons(ce->ra->xmit_seq++);
+               (void)sendto(state.sockfd, out_data, out_dlen, 0,
+                               (struct sockaddr *)&ce->ra->real_addr,
+                               sizeof_sockaddr(&ce->ra->real_addr));
+       } else {
+               unsigned i;
+               for (i = 0; i < RA_SET_HASH_SIZE; i++) {
+                       struct ra_entry *re;
+                       list_for_each_entry (re, &ra_set_hbase[i], list) {
+                               nmsg->hdr.seq = htons(re->xmit_seq++);
+                               (void)sendto(state.sockfd, out_data, out_dlen, 0,
+                                               (struct sockaddr *)&re->real_addr,
+                                               sizeof_sockaddr(&re->real_addr));
+                       }
+               }
+       }
+
+       return 0;
+}
+
+static void usr1_signal_handler(int signum)
+{
+}
+
+int run_server(const char *loc_addr_pair)
+{
+       char s_loc_addr[50];
+       bool is_random_port = false;
+    struct server_buffers buffers;
+
+    buffers.size = MTU_TO_BUFFER_SIZE(config.tun_mtu);
+    buffers.read_buffer = malloc(buffers.size);
+    buffers.crypt_buffer = malloc(buffers.size);
+    buffers.tun_buffer = malloc(buffers.size);
+    if (!buffers.read_buffer || !buffers.crypt_buffer || !buffers.tun_buffer) {
+        PLOG("Failed to allocate server buffers");
+        exit(1);
+    }
+
+       if (get_sockaddr_inx_pair(loc_addr_pair, &state.local_addr, &is_random_port) < 0) {
+               LOG("*** Cannot resolve address pair '%s'.", loc_addr_pair);
+               return -1;
+       }
+       if (is_random_port) {
+               LOG("*** Port range is not allowed for server.");
+               return -1;
+       }
+
+       inet_ntop(state.local_addr.sa.sa_family, addr_of_sockaddr(&state.local_addr),
+                       s_loc_addr, sizeof(s_loc_addr));
+       LOG("Server on %s:%u, interface: %s.",
+                       s_loc_addr, ntohs(port_of_sockaddr(&state.local_addr)), config.ifname);
+
+       init_va_ra_maps();
+       hash_initval = rand();
+
+       if ((state.sockfd = socket(state.local_addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
+               PLOG("*** socket() failed");
+               exit(1);
+       }
+       if (bind(state.sockfd, (struct sockaddr *)&state.local_addr,
+                sizeof_sockaddr(&state.local_addr)) < 0) {
+               PLOG("*** bind() failed");
+               exit(1);
+       }
+       set_nonblock(state.sockfd);
+
+
+       if (config.pid_file) {
+               FILE *fp;
+               if ((fp = fopen(config.pid_file, "w"))) {
+                       fprintf(fp, "%d\n", (int)getpid());
+                       fclose(fp);
+               }
+       }
+
+       gettimeofday(&state.last_walk, NULL);
+
+       signal(SIGUSR1, usr1_signal_handler);
+
+       for (;;) {
+               fd_set rset;
+               struct timeval __current, timeo;
+               int rc;
+
+               FD_ZERO(&rset);
+               FD_SET(state.tunfd, &rset);
+               FD_SET(state.sockfd, &rset);
+
+               timeo = (struct timeval) { 2, 0 };
+               rc = select((state.tunfd > state.sockfd ? state.tunfd : state.sockfd) + 1,
+                               &rset, NULL, NULL, &timeo);
+               if (rc < 0) {
+                       if (errno == EINTR || errno == ERESTART) continue;
+            PLOG("*** select() failed");
+                       return -1;
+               }
+
+               if (FD_ISSET(state.sockfd, &rset)) {
+                       network_receiving(&buffers);
+               }
+
+               if (FD_ISSET(state.tunfd, &rset)) {
+                       tunnel_receiving(&buffers);
+               }
+
+               gettimeofday(&__current, NULL);
+               if (__sub_timeval_ms(&__current, &state.last_walk) >= 3 * 1000) {
+                       va_ra_walk_continue();
+                       state.last_walk = __current;
+               }
+       }
+
+    free(buffers.read_buffer);
+    free(buffers.crypt_buffer);
+    free(buffers.tun_buffer);
+
+       return 0;
+}
+
+#endif /* WITH_SERVER_MODE */
