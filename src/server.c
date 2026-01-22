/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#if WITH_SERVER_MODE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include "list.h"
#include "jhash.h"
#include "minivtun.h"
#include "log.h"

static __u32 hash_initval = 0;

struct server_buffers {
    size_t size;
    char *read_buffer;
    char *crypt_buffer;
    char *tun_buffer;
};

static void *vt_route_lookup(short af, const void *a)
{
	const union {
		struct in_addr in;
#if WITH_IPV6
		struct in6_addr in6;
#endif
	} *addr = a;
	struct vt_route *rt;

	for (rt = config.vt_routes; rt; rt = rt->next) {
		if (rt->af != af)
			continue;
		if (af == AF_INET) {
			if (rt->prefix == 0) {
				return &rt->gateway.in;
			} else {
				in_addr_t m = rt->prefix ? htonl(~((1U << (32 - rt->prefix)) - 1)) : 0;
				if ((addr->in.s_addr & m) == rt->network.in.s_addr)
					return &rt->gateway.in;
			}
		}
#if WITH_IPV6
        else if (af == AF_INET6) {
			if (rt->prefix == 0) {
				return &rt->gateway.in6;
			} else if (rt->prefix < 128) {
				struct in6_addr n = addr->in6;
				int i;
				n.s6_addr[rt->prefix / 8] &= ~((1 << (8 - rt->prefix % 8)) - 1);
				for (i = rt->prefix / 8 + 1; i < 16; i++)
					n.s6_addr[i] &= 0x00;
				if (is_in6_equal(&n, &rt->network.in6))
					return &rt->gateway.in6;
			}

		}
#endif
	}

	return NULL;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

struct ra_entry {
	struct list_head list;
	struct sockaddr_inx real_addr;
	struct timeval last_recv;
	__u16 xmit_seq;
	int refs;
};

#define RA_SET_HASH_SIZE  (1 << 3)
#define RA_SET_LIMIT_EACH_WALK  (10)
static struct list_head ra_set_hbase[RA_SET_HASH_SIZE];
static unsigned ra_set_len;

static inline __u32 real_addr_hash(const struct sockaddr_inx *sa)
{
#if WITH_IPV6
	if (sa->sa.sa_family == AF_INET6) {
		return jhash_2words(sa->sa.sa_family, sa->in6.sin6_port,
			jhash2((__u32 *)&sa->in6.sin6_addr, 4, hash_initval));
	} else
#endif
    {
		return jhash_3words(sa->sa.sa_family, sa->in.sin_port,
			sa->in.sin_addr.s_addr, hash_initval);
	}
}

static struct ra_entry *ra_get_or_create(const struct sockaddr_inx *sa)
{
	struct list_head *chain = &ra_set_hbase[
		real_addr_hash(sa) & (RA_SET_HASH_SIZE - 1)];
	struct ra_entry *re;
	char s_real_addr[50];

	list_for_each_entry (re, chain, list) {
		if (is_sockaddr_equal(&re->real_addr, sa)) {
			re->refs++;
			return re;
		}
	}

	if ((re = malloc(sizeof(*re))) == NULL) {
		PLOG("malloc for ra_entry failed");
		return NULL;
	}

	re->real_addr = *sa;
	re->xmit_seq = (__u16)rand();
	re->refs = 1;
	list_add_tail(&re->list, chain);
	ra_set_len++;

	inet_ntop(re->real_addr.sa.sa_family, addr_of_sockaddr(&re->real_addr),
			s_real_addr, sizeof(s_real_addr));
	LOG("New client [%s:%u]", s_real_addr,
			ntohs(port_of_sockaddr(&re->real_addr)));

	return re;
}

static inline void ra_put_no_free(struct ra_entry *re)
{
	assert(re->refs > 0);
	re->refs--;
}

static inline void ra_entry_release(struct ra_entry *re)
{
	char s_real_addr[50];

	assert(re->refs == 0);
	list_del(&re->list);
	ra_set_len--;

	inet_ntop(re->real_addr.sa.sa_family, addr_of_sockaddr(&re->real_addr),
			s_real_addr, sizeof(s_real_addr));
	LOG("Recycled client [%s:%u]", s_real_addr,
			ntohs(port_of_sockaddr(&re->real_addr)));

	free(re);
}

struct tun_addr {
	unsigned short af;
	union {
		struct in_addr in;
#if WITH_IPV6
		struct in6_addr in6;
#endif
		struct mac_addr mac;
	};
};
struct tun_client {
	struct list_head list;
	struct tun_addr virt_addr;
	struct ra_entry *ra;
	struct timeval last_recv;
};

#define VA_MAP_HASH_SIZE  (1 << 4)
#define VA_MAP_LIMIT_EACH_WALK  (10)
static struct list_head va_map_hbase[VA_MAP_HASH_SIZE];
static unsigned va_map_len;

static inline void init_va_ra_maps(void)
{
	int i;

	for (i = 0; i < VA_MAP_HASH_SIZE; i++)
		INIT_LIST_HEAD(&va_map_hbase[i]);
	va_map_len = 0;

	for (i = 0; i < RA_SET_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ra_set_hbase[i]);
	ra_set_len = 0;
}

static inline __u32 tun_addr_hash(const struct tun_addr *addr)
{
	if (addr->af == AF_INET) {
		return jhash_2words(addr->af, addr->in.s_addr, hash_initval);
	}
#if WITH_IPV6
    else if (addr->af == AF_INET6) {
		const __be32 *a = (void *)&addr->in6;
		return jhash_2words(a[2], a[3],
			jhash_3words(addr->af, a[0], a[1], hash_initval));
	}
#endif
    else if (addr->af == AF_MACADDR) {
		const __be32 *a = (void *)&addr->mac;
		const __be16 *b = (void *)(a + 1);
		return jhash_3words(addr->af, *a, *b, hash_initval);
	} else {
		abort();
		return 0;
	}
}

static inline int tun_addr_comp(
		const struct tun_addr *a1, const struct tun_addr *a2)
{
	if (a1->af != a2->af) return 1;

	if (a1->af == AF_INET) {
		return (a1->in.s_addr == a2->in.s_addr) ? 0 : 1;
	}
#if WITH_IPV6
    else if (a1->af == AF_INET6) {
		return is_in6_equal(&a1->in6, &a2->in6) ? 0 : 1;
	}
#endif
    else if (a1->af == AF_MACADDR) {
		return is_mac_equal(&a1->mac, &a2->mac) ? 0 : 1;
	} else {
		abort();
		return 0;
	}
}

static void tun_addr_ntop(const struct tun_addr *a, char *buf, socklen_t bufsz)
{
	const __u8 *b;

	switch (a->af) {
	case AF_INET:
#if WITH_IPV6
	case AF_INET6:
#endif
		inet_ntop(a->af, &a->in, buf, bufsz);
		break;
	default:
		b = a->mac.addr;
		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
				b[0], b[1], b[2], b[3], b[4], b[5]);
	}
}

static inline void tun_client_release(struct tun_client *ce)
{
	char s_virt_addr[50], s_real_addr[50];

	tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
			s_real_addr, sizeof(s_real_addr));
	LOG("Recycled virtual address [%s] at [%s:%u].", s_virt_addr,
			s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)));

	ra_put_no_free(ce->ra);

	list_del(&ce->list);
	va_map_len--;

	free(ce);
}

static struct tun_client *tun_client_try_get(const struct tun_addr *vaddr)
{
	struct list_head *chain = &va_map_hbase[
		tun_addr_hash(vaddr) & (VA_MAP_HASH_SIZE - 1)];
	struct tun_client *ce;

	list_for_each_entry (ce, chain, list) {
		if (tun_addr_comp(&ce->virt_addr, vaddr) == 0)
			return ce;
	}
	return NULL;
}

static struct tun_client *tun_client_get_or_create(
		const struct tun_addr *vaddr, const struct sockaddr_inx *raddr)
{
	struct list_head *chain = &va_map_hbase[
		tun_addr_hash(vaddr) & (VA_MAP_HASH_SIZE - 1)];
	struct tun_client *ce, *__ce;
	char s_virt_addr[50], s_real_addr[50];

	list_for_each_entry_safe (ce, __ce, chain, list) {
		if (tun_addr_comp(&ce->virt_addr, vaddr) == 0) {
			if (!is_sockaddr_equal(&ce->ra->real_addr, raddr)) {
				ra_put_no_free(ce->ra);
				if ((ce->ra = ra_get_or_create(raddr)) == NULL) {
					tun_client_release(ce);
					return NULL;
				}
			}
			return ce;
		}
	}

	if ((ce = malloc(sizeof(*ce))) == NULL) {
		PLOG("malloc for tun_client failed");
		return NULL;
	}

	ce->virt_addr = *vaddr;

	if ((ce->ra = ra_get_or_create(raddr)) == NULL) {
		free(ce);
		return NULL;
	}
	list_add_tail(&ce->list, chain);
	va_map_len++;

	tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
			  s_real_addr, sizeof(s_real_addr));
	LOG("New virtual address [%s] at [%s:%u].", s_virt_addr,
			s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)));

	return ce;
}

static void reply_an_echo_ack(struct minivtun_msg *req, struct ra_entry *re)
{
	char in_data[64], crypt_buffer[64];
	struct minivtun_msg *nmsg = (struct minivtun_msg *)in_data;
	void *out_msg;
	size_t out_len;

	memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
	nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_ACK;
	nmsg->hdr.seq = htons(re->xmit_seq++);
	/* Fill echo fields */
	nmsg->echo = req->echo;

	/* Encrypt first */
	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	/* Compute HMAC on ciphertext (only if encryption is enabled) */
	if (state.crypto_ctx) {
		struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)out_msg;
		/* Zero auth_key field before computing HMAC (Encrypt-then-MAC) */
		memset(encrypted_msg->hdr.auth_key, 0, sizeof(encrypted_msg->hdr.auth_key));
		crypto_compute_hmac(state.crypto_ctx, encrypted_msg, out_len,
		                    encrypted_msg->hdr.auth_key, sizeof(encrypted_msg->hdr.auth_key));
	}

	(void)sendto(state.sockfd, out_msg, out_len, 0,
			(const struct sockaddr *)&re->real_addr,
			sizeof_sockaddr(&re->real_addr));
}

static void va_ra_walk_continue(void)
{
	static unsigned va_index = 0, ra_index = 0;
	struct timeval __current;
	unsigned va_walk_max = VA_MAP_LIMIT_EACH_WALK, va_count = 0;
	unsigned ra_walk_max = RA_SET_LIMIT_EACH_WALK, ra_count = 0;
	unsigned __va_index = va_index, __ra_index = ra_index;
	struct tun_client *ce, *__ce;
	struct ra_entry *re, *__re;

	gettimeofday(&__current, NULL);

	if (va_walk_max > va_map_len) va_walk_max = va_map_len;
	if (ra_walk_max > ra_set_len) ra_walk_max = ra_set_len;

	if (va_walk_max > 0) {
		do {
			list_for_each_entry_safe (ce, __ce, &va_map_hbase[va_index], list) {
				if (__sub_timeval_ms(&__current, &ce->last_recv) >
					config.reconnect_timeo * 1000) {
					tun_client_release(ce);
				}
				va_count++;
			}
			va_index = (va_index + 1) & (VA_MAP_HASH_SIZE - 1);
		} while (va_count < va_walk_max && va_index != __va_index);
	}

	if (ra_walk_max > 0) {
		do {
			list_for_each_entry_safe (re, __re, &ra_set_hbase[ra_index], list) {
				if (__sub_timeval_ms(&__current, &re->last_recv) >
					config.reconnect_timeo * 1000) {
					if (re->refs == 0) {
						ra_entry_release(re);
					}
				}
				ra_count++;
			}
			ra_index = (ra_index + 1) & (RA_SET_HASH_SIZE - 1);
		} while (ra_count < ra_walk_max && ra_index != __ra_index);
	}

	LOG("Online clients: %u, addresses: %u", ra_set_len, va_map_len);
}

static inline void source_addr_of_ipdata(
		const void *data, unsigned char af, struct tun_addr *addr)
{
	addr->af = af;
	switch (af) {
	case AF_INET:
		memcpy(&addr->in, (char *)data + 12, 4);
		break;
#if WITH_IPV6
	case AF_INET6:
		memcpy(&addr->in6, (char *)data + 8, 16);
		break;
#endif
	case AF_MACADDR:
		memcpy(&addr->mac, (char *)data + 6, 6);
		break;
	default:
		abort();
	}
}

static inline void dest_addr_of_ipdata(
		const void *data, unsigned char af, struct tun_addr *addr)
{
	addr->af = af;
	switch (af) {
	case AF_INET:
		memcpy(&addr->in, (char *)data + 16, 4);
		break;
#if WITH_IPV6
	case AF_INET6:
		memcpy(&addr->in6, (char *)data + 24, 16);
		break;
#endif
	case AF_MACADDR:
		memcpy(&addr->mac, (char *)data + 0, 6);
		break;
	default:
		abort();
	}
}


static int network_receiving(struct server_buffers* buffers)
{
	struct minivtun_msg *nmsg;
	void *out_data;
	size_t ip_dlen, out_dlen;
	unsigned short af = 0;
	struct tun_addr virt_addr;
	struct tun_client *ce;
	struct ra_entry *re;
	struct sockaddr_inx real_peer;
	socklen_t real_peer_alen;
	struct iovec iov[2];
    char pi_buf[sizeof(struct tun_pi)];
    struct tun_pi* pi = (struct tun_pi*)pi_buf;
	struct timeval __current;
	int rc;

	gettimeofday(&__current, NULL);

	real_peer_alen = sizeof(real_peer);
	rc = recvfrom(state.sockfd, buffers->read_buffer, buffers->size, 0,
			(struct sockaddr *)&real_peer, &real_peer_alen);
	if (rc <= 0)
		return -1;

	/* Verify HMAC on ciphertext BEFORE decryption */
	if (state.crypto_ctx) {
		struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)buffers->read_buffer;
		if (!crypto_verify_hmac(state.crypto_ctx, encrypted_msg, (size_t)rc)) {
			LOG("HMAC verification failed from client");
			return 0;
		}
	}

	out_data = buffers->crypt_buffer;
	out_dlen = (size_t)rc;
	if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
        LOG("Decryption failed");
        return 0;
    }
	nmsg = out_data;

	if (out_dlen < MINIVTUN_MSG_BASIC_HLEN)
		return 0;

	switch (nmsg->hdr.opcode) {
	case MINIVTUN_MSG_ECHO_REQ:
		if ((re = ra_get_or_create(&real_peer))) {
			re->last_recv = __current;
			reply_an_echo_ack(nmsg, re);
			ra_put_no_free(re);
		}
		if (out_dlen < MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo))
			return 0;
		if (config.tap_mode) {
			if (is_valid_unicast_mac(&nmsg->echo.loc_tun_mac)) {
				virt_addr.af = AF_MACADDR;
				virt_addr.mac = nmsg->echo.loc_tun_mac;
				if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
					ce->last_recv = __current;
			}
		} else {
			if (is_valid_unicast_in(&nmsg->echo.loc_tun_in)) {
				virt_addr.af = AF_INET;
				virt_addr.in = nmsg->echo.loc_tun_in;
				if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
					ce->last_recv = __current;
			}
#if WITH_IPV6
			if (is_valid_unicast_in6(&nmsg->echo.loc_tun_in6)) {
				virt_addr.af = AF_INET6;
				virt_addr.in6 = nmsg->echo.loc_tun_in6;
				if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
					ce->last_recv = __current;
			}
#endif
		}
		break;
	case MINIVTUN_MSG_IPDATA:
		if (config.tap_mode) {
			af = AF_MACADDR;
			if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 14) return 0;
			nmsg->ipdata.proto = 0;
			ip_dlen = out_dlen - MINIVTUN_MSG_IPDATA_OFFSET;
		} else {
			if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
				af = AF_INET;
				if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20) return 0;
			}
#if WITH_IPV6
            else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
				af = AF_INET6;
				if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 40) return 0;
			}
#endif
            else {
				LOG("*** Invalid protocol: 0x%x.", ntohs(nmsg->ipdata.proto));
				return 0;
			}
			ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
			if (out_dlen - MINIVTUN_MSG_IPDATA_OFFSET < ip_dlen)
				return 0;
		}

		source_addr_of_ipdata(nmsg->ipdata.data, af, &virt_addr);
		if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)) == NULL)
			return 0;

		ce->last_recv = __current;
		ce->ra->last_recv = __current;

		pi->flags = 0;
		pi->proto = nmsg->ipdata.proto;
		iov[0].iov_base = pi;
		iov[0].iov_len = sizeof(*pi);
		iov[1].iov_base = nmsg->ipdata.data;
		iov[1].iov_len = ip_dlen;
		rc = writev(state.tunfd, iov, 2);
		break;
	}

	return 0;
}

static int tunnel_receiving(struct server_buffers* buffers)
{
    struct minivtun_msg *nmsg = (struct minivtun_msg *)buffers->crypt_buffer;
    struct tun_pi *pi = (struct tun_pi *)buffers->tun_buffer;
	void *out_data;
	size_t ip_dlen, out_dlen;
	unsigned short af = 0;
	struct tun_addr virt_addr;
	struct tun_client *ce;
	int rc;

	rc = read(state.tunfd, pi, buffers->size);
    if (rc <= 0) return -1;
	if ((size_t)rc < sizeof(struct tun_pi)) return -1;

	ip_dlen = (size_t)rc - sizeof(struct tun_pi);

	if (config.tap_mode) {
		af = AF_MACADDR;
		if (ip_dlen < 14) return 0;
	} else {
		if (pi->proto == htons(ETH_P_IP)) {
			af = AF_INET;
			if (ip_dlen < 20) return 0;
		}
#if WITH_IPV6
        else if (pi->proto == htons(ETH_P_IPV6)) {
			af = AF_INET6;
			if (ip_dlen < 40) return 0;
		}
#endif
        else {
			LOG("*** Invalid protocol from tun: 0x%x.", ntohs(pi->proto));
			return 0;
		}
	}

	dest_addr_of_ipdata(pi + 1, af, &virt_addr);

	if ((ce = tun_client_try_get(&virt_addr)) == NULL) {
		void *gw;
		if ((gw = vt_route_lookup(virt_addr.af, &virt_addr.in))) {
			struct tun_addr __va;
			memset(&__va, 0x0, sizeof(__va));
			__va.af = virt_addr.af;
			if (virt_addr.af == AF_INET) {
				__va.in = *(struct in_addr *)gw;
			}
#if WITH_IPV6
            else if (virt_addr.af == AF_INET6) {
				__va.in6 = *(struct in6_addr *)gw;
			}
#endif
            else {
				__va.mac = *(struct mac_addr *)gw;
			}
			if ((ce = tun_client_try_get(&__va)) == NULL)
				return 0;

			if ((ce = tun_client_get_or_create(&virt_addr,
				&ce->ra->real_addr)) == NULL)
				return 0;
		} else if (config.tap_mode) {
            // In tap mode, broadcast to all clients if dest is unknown
            ce = NULL;
		} else {
			return 0;
		}
	}

	memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
	nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
	/* Fill ipdata fields */
	nmsg->ipdata.proto = pi->proto;
	nmsg->ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

	/* Encrypt first (auth_key already zero from memset above) */
	out_data = buffers->read_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	if(local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
        LOG("Encryption failed");
        return 0;
    }

	/* Compute HMAC on ciphertext with actual encrypted length */
	if (state.crypto_ctx) {
		struct minivtun_msg *encrypted_msg = (struct minivtun_msg *)out_data;
		/* Zero auth_key field before computing HMAC (Encrypt-then-MAC) */
		memset(encrypted_msg->hdr.auth_key, 0, sizeof(encrypted_msg->hdr.auth_key));
		crypto_compute_hmac(state.crypto_ctx, encrypted_msg, out_dlen,
		                    encrypted_msg->hdr.auth_key, sizeof(encrypted_msg->hdr.auth_key));
	}

	if (ce) {
		nmsg->hdr.seq = htons(ce->ra->xmit_seq++);
		(void)sendto(state.sockfd, out_data, out_dlen, 0,
				(struct sockaddr *)&ce->ra->real_addr,
				sizeof_sockaddr(&ce->ra->real_addr));
	} else {
		unsigned i;
		for (i = 0; i < RA_SET_HASH_SIZE; i++) {
			struct ra_entry *re;
			list_for_each_entry (re, &ra_set_hbase[i], list) {
				nmsg->hdr.seq = htons(re->xmit_seq++);
				(void)sendto(state.sockfd, out_data, out_dlen, 0,
						(struct sockaddr *)&re->real_addr,
						sizeof_sockaddr(&re->real_addr));
			}
		}
	}

	return 0;
}

static void usr1_signal_handler(int signum)
{
}

int run_server(const char *loc_addr_pair)
{
	char s_loc_addr[50];
	bool is_random_port = false;
    struct server_buffers buffers;

    buffers.size = MTU_TO_BUFFER_SIZE(config.tun_mtu);
    buffers.read_buffer = malloc(buffers.size);
    buffers.crypt_buffer = malloc(buffers.size);
    buffers.tun_buffer = malloc(buffers.size);
    if (!buffers.read_buffer || !buffers.crypt_buffer || !buffers.tun_buffer) {
        PLOG("Failed to allocate server buffers");
        exit(1);
    }

	if (get_sockaddr_inx_pair(loc_addr_pair, &state.local_addr, &is_random_port) < 0) {
		LOG("*** Cannot resolve address pair '%s'.", loc_addr_pair);
		return -1;
	}
	if (is_random_port) {
		LOG("*** Port range is not allowed for server.");
		return -1;
	}

	inet_ntop(state.local_addr.sa.sa_family, addr_of_sockaddr(&state.local_addr),
			s_loc_addr, sizeof(s_loc_addr));
	LOG("Server on %s:%u, interface: %s.",
			s_loc_addr, ntohs(port_of_sockaddr(&state.local_addr)), config.ifname);

	init_va_ra_maps();
	hash_initval = rand();

	if ((state.sockfd = socket(state.local_addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		PLOG("*** socket() failed");
		exit(1);
	}
	if (bind(state.sockfd, (struct sockaddr *)&state.local_addr,
		sizeof_sockaddr(&state.local_addr)) < 0) {
		PLOG("*** bind() failed");
		exit(1);
	}
	set_nonblock(state.sockfd);


	if (config.pid_file) {
		FILE *fp;
		if ((fp = fopen(config.pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)getpid());
			fclose(fp);
		}
	}

	gettimeofday(&state.last_walk, NULL);

	signal(SIGUSR1, usr1_signal_handler);

	for (;;) {
		fd_set rset;
		struct timeval __current, timeo;
		int rc;

		FD_ZERO(&rset);
		FD_SET(state.tunfd, &rset);
		FD_SET(state.sockfd, &rset);

		timeo = (struct timeval) { 2, 0 };
		rc = select((state.tunfd > state.sockfd ? state.tunfd : state.sockfd) + 1,
				&rset, NULL, NULL, &timeo);
		if (rc < 0) {
			if (errno == EINTR || errno == ERESTART) continue;
            PLOG("*** select() failed");
			return -1;
		}

		if (FD_ISSET(state.sockfd, &rset)) {
			network_receiving(&buffers);
		}

		if (FD_ISSET(state.tunfd, &rset)) {
			tunnel_receiving(&buffers);
		}

		gettimeofday(&__current, NULL);
		if (__sub_timeval_ms(&__current, &state.last_walk) >= 3 * 1000) {
			va_ra_walk_continue();
			state.last_walk = __current;
		}
	}

    free(buffers.read_buffer);
    free(buffers.crypt_buffer);
    free(buffers.tun_buffer);

	return 0;
}

#endif /* WITH_SERVER_MODE */
