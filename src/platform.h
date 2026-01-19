/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * Platform-specific network functions
 */

#ifndef __PLATFORM_H
#define __PLATFORM_H

#include "library.h"

int plat_tun_alloc(char *dev, bool tap_mode);

void plat_ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
		struct in_addr *peer, int prefix);

#ifdef WITH_IPV6
void plat_ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix);
#endif

void plat_ip_link_set_mtu(const char *ifname, unsigned mtu);
void plat_ip_link_set_txqueue_len(const char *ifname, unsigned qlen);
void plat_ip_link_set_updown(const char *ifname, bool up);

void plat_ip_route_add(int af, const char *ifname, void *network, int prefix,
		int metric, const char *table);

#ifdef WITH_DAEMONIZE
void plat_daemonize(void);
#endif

#endif /* __PLATFORM_H */
