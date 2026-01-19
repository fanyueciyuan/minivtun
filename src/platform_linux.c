/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * Linux platform-specific functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_tun.h>

#include "minivtun.h"
#include "library.h"
#include "list.h"
#include "jhash.h"
#include "log.h"
#include "platform.h"

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
    ifr.ifr_flags |= IFF_NO_PI; // We provide protocol info manually

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

/* Like strncpy but make sure the resulting string is always 0 terminated. */
static char *safe_strncpy(char *dst, const char *src, size_t size)
{
	dst[size - 1] = '\0';
	return strncpy(dst, src, size - 1);
}

static int __get_ifindex(const char *ifname)
{
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	memset(&ifr, 0x0, sizeof(ifr));
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOGIFINDEX, &ifr) < 0) {
		close(sockfd);
		return -1;
	}
	close(sockfd);
	return ifr.ifr_ifindex;
}

static int __set_flag(int sockfd, const char *ifname, short flag)
{
	struct ifreq ifr;

	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		PLOG("ioctl(SIOCGIFFLAGS) failed for %s", ifname);
		return -1;
	}
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags |= flag;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		PLOG("ioctl(SIOCSIFFLAGS) failed for %s", ifname);
		return -1;
	}
	return 0;
}

static int __clr_flag(int sockfd, const char *ifname, short flag)
{
	struct ifreq ifr;

	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		PLOG("ioctl(SIOCGIFFLAGS) failed for %s", ifname);
		return -1;
	}
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags &= ~flag;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		PLOG("ioctl(SIOCSIFFLAGS) failed for %s", ifname);
		return -1;
	}
	return 0;
}

static int __set_ip_using(int sockfd, const char *name, int c,
		const struct in_addr *addr)
{
	struct sockaddr_in sin;
	struct ifreq ifr;

	safe_strncpy(ifr.ifr_name, name, IFNAMSIZ);
	memset(&sin, 0, sizeof(struct sockaddr));
	sin.sin_family = AF_INET;
	sin.sin_addr = *addr;
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	if (ioctl(sockfd, c, &ifr) < 0)
		return -1;
	return 0;
}


void plat_ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
		struct in_addr *peer, int prefix)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PLOG("socket() failed");
		return;
    }

	if (is_valid_unicast_in(local) && is_valid_unicast_in(peer)) {
		__set_ip_using(sockfd, ifname, SIOCSIFADDR, local);
		__set_ip_using(sockfd, ifname, SIOCSIFDSTADDR, peer);
		__set_flag(sockfd, ifname, IFF_POINTOPOINT | IFF_UP | IFF_RUNNING);
	} else if (is_valid_unicast_in(local) && prefix > 0) {
		struct in_addr mask;
		mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));
		__set_ip_using(sockfd, ifname, SIOCSIFADDR, local);
		__set_ip_using(sockfd, ifname, SIOCSIFNETMASK, &mask);
		__set_flag(sockfd, ifname, IFF_UP | IFF_RUNNING);
	}
	close(sockfd);
}

#ifdef WITH_IPV6
void plat_ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix)
{
	struct in6_ifreq {
		struct in6_addr ifr6_addr;
		__u32 ifr6_prefixlen;
		unsigned int ifr6_ifindex;
	};
	struct in6_ifreq ifr6;
	int sockfd, ifindex;

	if ((ifindex = __get_ifindex(ifname)) < 0) {
		PLOG("SIOGIFINDEX failed for %s", ifname);
		return;
	}
	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        PLOG("socket(AF_INET6) failed");
		return;
    }
	if (is_valid_unicast_in6(local) && prefix > 0) {
		memcpy(&ifr6.ifr6_addr, local, sizeof(*local));
		ifr6.ifr6_ifindex = ifindex;
		ifr6.ifr6_prefixlen = prefix;
		if (ioctl(sockfd, SIOCSIFADDR, &ifr6) < 0)
			PLOG("ioctl(SIOCSIFADDR) for IPv6 failed");
	}
	close(sockfd);
}
#endif

void plat_ip_link_set_mtu(const char *ifname, unsigned mtu)
{
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
         PLOG("socket() failed");
		return;
    }
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_mtu = mtu;
	if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0)
		PLOG("ioctl(SIOCSIFMTU) to %u failed", mtu);
	close(sockfd);
}

void plat_ip_link_set_txqueue_len(const char *ifname, unsigned qlen)
{
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PLOG("socket() failed");
		return;
    }
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_qlen = qlen;
	if (ioctl(sockfd, SIOCSIFTXQLEN, &ifr) < 0)
		PLOG("ioctl(SIOCSIFTXQLEN) failed");
	close(sockfd);
}

void plat_ip_link_set_updown(const char *ifname, bool up)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PLOG("socket() failed");
		return;
    }
	if (up) {
		__set_flag(sockfd, ifname, IFF_UP | IFF_RUNNING);
	} else {
		__clr_flag(sockfd, ifname, IFF_UP);
	}
	close(sockfd);
}


void plat_ip_route_add(int af, const char *ifname, void *network, int prefix,
		int metric, const char *table)
{
	if (table) {
		char cmd[256], __net[64] = "";
		inet_ntop(af, network, __net, sizeof(__net));
		sprintf(cmd, "ip %s route add %s/%d dev %s metric %d table %s",
			af == AF_INET6 ? "-6" : "", __net, prefix, ifname, metric, table);
		if (system(cmd) != 0) {
            LOG("system('%s') failed", cmd);
        }
        return;
	}

#ifdef WITH_IPV6
	if (af == AF_INET6) {
		struct in6_rtmsg {
			struct in6_addr rtmsg_dst;
			__u16 rtmsg_dst_len;
			__u16 rtmsg_flags;
			__u32 rtmsg_metric;
			int rtmsg_ifindex;
		} rt6;
		int sockfd, ifindex;

		if ((ifindex = __get_ifindex(ifname)) < 0) {
			PLOG("SIOGIFINDEX failed for %s", ifname);
			return;
		}

		memset(&rt6, 0x0, sizeof(rt6));
		memcpy(&rt6.rtmsg_dst, network, sizeof(struct in6_addr));
		rt6.rtmsg_flags = RTF_UP;
		if (prefix == 128)
			rt6.rtmsg_flags |= RTF_HOST;
		rt6.rtmsg_metric = metric;
		rt6.rtmsg_dst_len = prefix;
		rt6.rtmsg_ifindex = ifindex;

		if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
			PLOG("socket(AF_INET6) failed");
			return;
		}
		if(ioctl(sockfd, SIOCADDRT, &rt6) < 0) {
            PLOG("ioctl(SIOCADDRT) for IPv6 failed");
        }
		close(sockfd);
        return;
	}
#endif

	if (af == AF_INET) {
		struct rtentry rt;
		int sockfd;

		memset(&rt, 0x0, sizeof(rt));
		rt.rt_flags = RTF_UP;
		if (prefix == 32)
			rt.rt_flags |= RTF_HOST;
		((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
		((struct sockaddr_in *)&rt.rt_dst)->sin_addr = *(struct in_addr *)network;
		((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
		((struct sockaddr_in *)&rt.rt_genmask)->sin_addr.s_addr =
				prefix ? htonl(~((1 << (32 - prefix)) - 1)) : 0;
		rt.rt_metric = metric + 1; /* +1 for binary compatibility! */
		rt.rt_dev = (char *)ifname;
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			PLOG("socket() failed");
			return;
		}
		if(ioctl(sockfd, SIOCADDRT, &rt) < 0) {
            PLOG("ioctl(SIOCADDRT) for IPv4 failed");
        }
		close(sockfd);
	}
}


#ifdef WITH_DAEMONIZE
void plat_daemonize(void)
{
	pid_t pid;
	int fd;

	if ((pid = fork()) < 0) {
		PLOG("fork() failed");
		exit(1);
	}
	if (pid > 0) {
		exit(0);
	}

	if (setsid() < 0) {
        PLOG("setsid() failed");
		exit(1);
    }

	signal(SIGHUP, SIG_IGN);

	if ((pid = fork()) < 0) {
		PLOG("fork() failed");
		exit(1);
	}
	if (pid > 0) {
		exit(0);
	}

	umask(0);
    chdir("/");

	for (fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
		close(fd);
	}

    fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }
}
#endif
