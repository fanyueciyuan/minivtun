/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#ifndef __MINIVTUN_H
#define __MINIVTUN_H

#include "library.h"
#include "platform.h"
#include "crypto_wrapper.h"

extern struct minivtun_config config;
extern struct state_variables state;

/**
* Pseudo route table for binding client side subnets
* to corresponding connected virtual addresses.
*/
struct vt_route {
	struct vt_route *next;
	short af;
	union {
		struct in_addr in;
#if WITH_IPV6
		struct in6_addr in6;
#endif
	} network, gateway;
	int prefix;
};

struct minivtun_config {
	char ifname[40];
	unsigned tun_mtu;
	unsigned tun_qlen;
	const char *crypto_algo;
	const char *crypto_passwd;
	const char *pid_file;
	bool in_background;
	bool tap_mode;

	/* IPv4 address settings */
	struct in_addr tun_in_local;
	struct in_addr tun_in_peer;
	int tun_in_prefix;

#if WITH_IPV6
	/* IPv6 address settings */
	struct in6_addr tun_in6_local;
	int tun_in6_prefix;
#endif

	/* Dynamic routes for client, or virtual routes for server */
	struct vt_route *vt_routes;

#if WITH_CLIENT_MODE
	/* Client only configuration */
	bool wait_dns;
	unsigned exit_after;
	bool dynamic_link;
	unsigned reconnect_timeo;
	unsigned max_droprate;
	unsigned max_rtt;
	unsigned keepalive_interval;
	unsigned health_assess_interval;
	unsigned nr_stats_buckets;
	const char *health_file;
	unsigned vt_metric;
	int metric_stepping; /* dynamic link route metric stepping factor */
	char vt_table[32];
#endif
};

/* Statistics data for health assess */
struct stats_data {
	unsigned total_echo_sent;
	unsigned total_echo_rcvd;
	unsigned long total_rtt_ms;
};

static inline void zero_stats_data(struct stats_data *st)
{
	st->total_echo_sent = 0;
	st->total_echo_rcvd = 0;
	st->total_rtt_ms = 0;
}

/* Status variables during VPN running */
struct state_variables {
	int tunfd;
	int sockfd;
	struct crypto_context *crypto_ctx;

#if WITH_CLIENT_MODE
	/* *** Client specific *** */
	struct sockaddr_inx peer_addr;
	__u16 xmit_seq;
	struct timeval last_recv;
	struct timeval last_echo_sent;
	struct timeval last_echo_recv;
	struct timeval last_health_assess;
	bool is_link_ok;
	bool health_based_link_up;
	unsigned rt_metric; /* current route metric */

	/* Health assess data */
	bool has_pending_echo;
	__be32 pending_echo_id;
	struct stats_data *stats_buckets;
	unsigned current_bucket;
#endif

#if WITH_SERVER_MODE
	/* *** Server specific *** */
	struct sockaddr_inx local_addr;
	struct timeval last_walk;
#endif
};

enum {
	MINIVTUN_MSG_ECHO_REQ,
	MINIVTUN_MSG_IPDATA,
	MINIVTUN_MSG_DISCONNECT,
	MINIVTUN_MSG_ECHO_ACK,
};

// Make buffer size dynamic based on MTU, allowing for IP headers and crypto overhead
#define MTU_TO_BUFFER_SIZE(mtu) (mtu + 512)

struct minivtun_msg {
	struct {
		__u8 opcode;
		__u8 rsv;
		__be16 seq;
		__u8 auth_key[16];
	} __attribute__((packed)) hdr; /* 20 */

	union {
		struct {
			__be16 proto;   /* ETH_P_IP or ETH_P_IPV6 */
			__be16 ip_dlen; /* Total length of IP/IPv6 data */
			char data[];    // Flexible array member
		} __attribute__((packed)) ipdata;
		struct {
			union {
				struct {
					struct in_addr loc_tun_in;
#if WITH_IPV6
					struct in6_addr loc_tun_in6;
#endif
				};
				struct mac_addr loc_tun_mac;
			};
			__be32 id;
		} __attribute__((packed)) echo; /* 24 */
	};
} __attribute__((packed));

#define MINIVTUN_MSG_BASIC_HLEN  (sizeof(((struct minivtun_msg *)0)->hdr))
#define MINIVTUN_MSG_IPDATA_OFFSET  (offsetof(struct minivtun_msg, ipdata.data))

#define enabled_encryption()  (config.crypto_passwd && config.crypto_passwd[0])

static inline int local_to_netmsg(void *in, void **out, size_t *dlen)
{
	return crypto_encrypt(state.crypto_ctx, in, *out, dlen);
}
static inline int netmsg_to_local(void *in, void **out, size_t *dlen)
{
	return crypto_decrypt(state.crypto_ctx, in, *out, dlen);
}

#if WITH_CLIENT_MODE
int run_client(const char *peer_addr_pair);
#endif
#if WITH_SERVER_MODE
int run_server(const char *loc_addr_pair);
#endif

#endif /* __MINIVTUN_H */

