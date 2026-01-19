/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * BSD/macOS platform-specific functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>

#include "log.h"
#include "platform.h"

/* Protocol info prepended to the packets */
struct tun_pi {
    __u16  flags;
    __be16 proto;
};
#define TUNSIFHEAD  _IOW('t', 96, int)
#define TUNGIFHEAD  _IOR('t', 97, int)

int plat_tun_alloc(char *dev, bool tap_mode)
{
    // Note: BSD/macOS does not have a clear separation between tun and tap
    // in the same way Linux does. The device name 'tun' is used.
	int fd = -1, i;
    char dev_path[20];

	for (i = 0; i < 16; i++) {
		sprintf(dev_path, "/dev/tun%d", i);
		if ((fd = open(dev_path, O_RDWR)) >= 0) {
			sprintf(dev, "tun%d", i);
			return fd;
		}
	}

    PLOG("Failed to open any /dev/tunX device");
	return -1;
}

/* Like strncpy but make sure the resulting string is always 0 terminated. */
static char *safe_strncpy(char *dst, const char *src, size_t size)
{
	dst[size - 1] = '\0';
	return strncpy(dst, src, size - 1);
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
	char cmd[256];
    char local_str[INET_ADDRSTRLEN];
    char peer_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, local, local_str, sizeof(local_str));

    if (is_valid_unicast_in(local) && is_valid_unicast_in(peer)) {
        inet_ntop(AF_INET, peer, peer_str, sizeof(peer_str));
        sprintf(cmd, "ifconfig %s %s %s up", ifname, local_str, peer_str);
    } else if (is_valid_unicast_in(local) && prefix > 0) {
        sprintf(cmd, "ifconfig %s %s/%d up", ifname, local_str, prefix);
    } else {
        return;
    }

    LOG("executing: %s", cmd);
    if(system(cmd) != 0) {
        LOG("Command failed: %s", cmd);
    }
}


#ifdef WITH_IPV6
void plat_ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix)
{
    char cmd[256];
    char local_str[INET6_ADDRSTRLEN];

    if (!is_valid_unicast_in6(local) || prefix <= 0) {
        return;
    }

    inet_ntop(AF_INET6, local, local_str, sizeof(local_str));
    sprintf(cmd, "ifconfig %s inet6 %s prefixlen %d up", ifname, local_str, prefix);

    LOG("executing: %s", cmd);
    if(system(cmd) != 0) {
        LOG("Command failed: %s", cmd);
    }
}
#endif

void plat_ip_link_set_mtu(const char *ifname, unsigned mtu)
{
    char cmd[256];
    sprintf(cmd, "ifconfig %s mtu %u", ifname, mtu);
    LOG("executing: %s", cmd);
    if(system(cmd) != 0) {
        LOG("Command failed: %s", cmd);
    }
}

// This is a Linux-specific feature
void plat_ip_link_set_txqueue_len(const char *ifname, unsigned qlen) {
    (void)ifname;
    (void)qlen;
    // Not supported on BSD/macOS
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
    // NOTE: This uses system() which is inefficient.
    // A proper implementation would use ioctl(SIOCADDRT) with struct rt_msghdr
    // but this is significantly more complex than the Linux version.
    // For now, we isolate the inefficient call here.
	char cmd[256], __net[64] = "";
	inet_ntop(af, network, __net, sizeof(__net));

    if (table) {
        LOG("Routing tables are not supported on BSD/macOS via this function");
        return;
    }

	sprintf(cmd, "route add -net %s/%d -interface %s",
		    __net, prefix, ifname);

    LOG("executing: %s", cmd);
    if(system(cmd) != 0) {
        LOG("Command failed: %s", cmd);
    }
}

#ifdef WITH_DAEMONIZE
void plat_daemonize(void)
{
	pid_t pid;

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

	if ((pid = fork()) < 0) {
		PLOG("fork() failed");
		exit(1);
	}
	if (pid > 0) {
		exit(0);
	}

    if (chdir("/tmp") < 0) {
        PLOG("chdir(/tmp) failed");
    }

	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
}
#endif
