/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#if WITH_CLIENT_MODE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include "minivtun.h"
#include "platform.h"
#include "log.h"

static bool rewind_dynamic_link_metric = false;

struct client_buffers {
    size_t size;
    char *read_buffer;
    char *crypt_buffer;
    char *tun_buffer;
};

static void handle_link_up(void)
{
	struct vt_route *rt;

	plat_ip_link_set_updown(config.ifname, true);

	if (config.metric_stepping) {
		LOG("Link is up, metric: %u.", state.rt_metric);
	} else {
		LOG("Link is up.");
	}

	plat_ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
			&config.tun_in_peer, config.tun_in_prefix);

#if WITH_IPV6
	plat_ip_addr_add_ipv6(config.ifname, &config.tun_in6_local,
			config.tun_in6_prefix);
#endif

	if (!config.tap_mode) {
		for (rt = config.vt_routes; rt; rt = rt->next) {
			plat_ip_route_add(rt->af, config.ifname, &rt->network, rt->prefix,
				state.rt_metric, config.vt_table[0] ? config.vt_table : NULL);
		}
	}
}

static void handle_link_down(void)
{
	plat_ip_link_set_updown(config.ifname, false);

	state.rt_metric += config.metric_stepping;

	LOG("Link is down.");
}

static int network_receiving(struct client_buffers *buffers)
{
	struct minivtun_msg *nmsg;
	void *out_data;
	size_t ip_dlen, out_dlen;
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

	out_data = buffers->crypt_buffer;
	out_dlen = (size_t)rc;
	if (netmsg_to_local(buffers->read_buffer, &out_data, &out_dlen) != 0) {
        LOG("Decryption failed.");
        return 0;
    }
	nmsg = out_data;

	if (out_dlen < MINIVTUN_MSG_BASIC_HLEN)
		return 0;

	/* Verify HMAC authentication */
	if (!crypto_verify_hmac(state.crypto_ctx, nmsg, out_dlen)) {
		LOG("HMAC verification failed - message authentication error");
		return 0;
	}

	state.last_recv = __current;

	if (!state.health_based_link_up) {
		if (!state.is_link_ok) {
			if (config.dynamic_link)
				handle_link_up();
			state.is_link_ok = true;
		}
	}

	switch (nmsg->hdr.opcode) {
	case MINIVTUN_MSG_IPDATA:
		if (config.tap_mode) {
			if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 14) return 0;
			ip_dlen = out_dlen - MINIVTUN_MSG_IPDATA_OFFSET;
			nmsg->ipdata.proto = 0;
		} else {
			if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
				if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20) return 0;
			}
#if WITH_IPV6
            else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
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

		pi->flags = 0;
		pi->proto = nmsg->ipdata.proto;
		iov[0].iov_base = pi;
		iov[0].iov_len = sizeof(*pi);
		iov[1].iov_base = nmsg->ipdata.data;
		iov[1].iov_len = ip_dlen;
		rc = writev(state.tunfd, iov, 2);
		break;
	case MINIVTUN_MSG_ECHO_ACK:
		if (state.has_pending_echo && nmsg->echo.id == state.pending_echo_id) {
			struct stats_data *st = &state.stats_buckets[state.current_bucket];
			st->total_echo_rcvd++;
			st->total_rtt_ms += __sub_timeval_ms(&__current, &state.last_echo_sent);
			state.last_echo_recv = __current;
			state.has_pending_echo = false;
		}
		break;
	}

	return 0;
}

static int tunnel_receiving(struct client_buffers *buffers)
{
    struct minivtun_msg *nmsg = (struct minivtun_msg *)buffers->crypt_buffer;
    struct tun_pi *pi = (struct tun_pi *)buffers->tun_buffer;
	void *out_data;
	size_t ip_dlen, out_dlen;
	int rc;

	rc = read(state.tunfd, pi, buffers->size);
    if (rc <= 0) return -1;

	// The first few bytes from TUN are protocol info
    if ((size_t)rc < sizeof(struct tun_pi)) return -1;
	ip_dlen = (size_t)rc - sizeof(struct tun_pi);

	if (config.tap_mode) {
		if (ip_dlen < 14) return 0;
	} else {
		if (pi->proto == htons(ETH_P_IP)) {
			if (ip_dlen < 20) return 0;
		}
#if WITH_IPV6
        else if (pi->proto == htons(ETH_P_IPV6)) {
			if (ip_dlen < 40) return 0;
		}
#endif
        else {
			LOG("*** Invalid protocol from tun: 0x%x.", ntohs(pi->proto));
			return 0;
		}
	}

	memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
	nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
	nmsg->hdr.seq = htons(state.xmit_seq++);
	/* Compute HMAC (auth_key field is currently zero) */
	size_t msg_len_for_hmac = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len_for_hmac,
	                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
	nmsg->ipdata.proto = pi->proto;
	nmsg->ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);

	out_data = buffers->read_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	if (local_to_netmsg(nmsg, &out_data, &out_dlen) != 0) {
        LOG("Encryption failed");
        return 0;
    }

	(void)send(state.sockfd, out_data, out_dlen, 0);

	return 0;
}

static void do_an_echo_request(void)
{
	char in_data[64], crypt_buffer[64];
	struct minivtun_msg *nmsg = (struct minivtun_msg *)in_data;
	void *out_msg;
	size_t out_len;
	size_t msg_len;
	__be32 r = rand();

	memset(nmsg, 0x0, sizeof(nmsg->hdr) + sizeof(nmsg->echo));
	nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_REQ;
	nmsg->hdr.seq = htons(state.xmit_seq++);
	/* Compute HMAC for ECHO request */
	msg_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
	crypto_compute_hmac(state.crypto_ctx, nmsg, msg_len,
	                    nmsg->hdr.auth_key, sizeof(nmsg->hdr.auth_key));
	if (!config.tap_mode) {
		nmsg->echo.loc_tun_in = config.tun_in_local;
#if WITH_IPV6
		nmsg->echo.loc_tun_in6 = config.tun_in6_local;
#endif
	}
	nmsg->echo.id = r;

	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	(void)send(state.sockfd, out_msg, out_len, 0);

	state.has_pending_echo = true;
	state.pending_echo_id = r;
	state.stats_buckets[state.current_bucket].total_echo_sent++;
}

static void reset_state_on_reconnect(void)
{
	struct timeval __current;
	int i;

	gettimeofday(&__current, NULL);
	state.xmit_seq = (__u16)rand();
	state.last_recv = __current;
	state.last_echo_recv = __current;
	state.last_echo_sent = (struct timeval) { 0, 0 };
	state.last_health_assess = __current;
	state.has_pending_echo = false;
	state.pending_echo_id = 0;

	for (i = 0; i < config.nr_stats_buckets; i++)
		zero_stats_data(&state.stats_buckets[i]);
	state.current_bucket = 0;
}

static bool do_link_health_assess(void)
{
	unsigned sent = 0, rcvd = 0, rtt = 0;
	unsigned drop_percent, rtt_average, i;
	bool health_ok = true;

	for (i = 0; i < config.nr_stats_buckets; i++) {
		struct stats_data *st = &state.stats_buckets[i];
		sent += st->total_echo_sent;
		rcvd += st->total_echo_rcvd;
		rtt += st->total_rtt_ms;
	}

	if (rcvd > sent) rcvd = sent;
	drop_percent = sent ? ((sent - rcvd) * 100 / sent) : 0;
	rtt_average = rcvd ? (rtt / rcvd) : 0;

	if (drop_percent > config.max_droprate) {
		health_ok = false;
	} else if (config.max_rtt && rtt_average > config.max_rtt) {
		health_ok = false;
	}

	if (config.health_file) {
		FILE *fp;
		remove(config.health_file);
		if ((fp = fopen(config.health_file, "w"))) {
			fprintf(fp, "%u,%u,%u,%u\n", sent, rcvd, drop_percent, rtt_average);
			fclose(fp);
		}
	} else {
		LOG("Health - sent: %u, received: %u, drop: %u%%, RTT: %ums",
				sent, rcvd, drop_percent, rtt_average);
	}

	state.current_bucket = (state.current_bucket + 1) % config.nr_stats_buckets;
	zero_stats_data(&state.stats_buckets[state.current_bucket]);

	if (!health_ok) {
		LOG("Unhealthy state - sent: %u, received: %u, drop: %u%%, RTT: %ums",
				sent, rcvd, drop_percent, rtt_average);
	}

	return health_ok;
}

static void usr1_signal_handler(int signum)
{
	rewind_dynamic_link_metric = true;
}

int run_client(const char *peer_addr_pair)
{
	char s_peer_addr[50];
	struct timeval startup_time;
    struct client_buffers buffers;

    buffers.size = MTU_TO_BUFFER_SIZE(config.tun_mtu);
    buffers.read_buffer = malloc(buffers.size);
    buffers.crypt_buffer = malloc(buffers.size);
    buffers.tun_buffer = malloc(buffers.size);
    if (!buffers.read_buffer || !buffers.crypt_buffer || !buffers.tun_buffer) {
        PLOG("Failed to allocate client buffers");
        exit(1);
    }

	state.stats_buckets = malloc(sizeof(struct stats_data) * config.nr_stats_buckets);
	assert(state.stats_buckets);

	gettimeofday(&startup_time, NULL);

	state.is_link_ok = false;
	if (config.dynamic_link)
		plat_ip_link_set_updown(config.ifname, false);

	state.rt_metric = config.vt_metric;

	if (config.wait_dns) {
		state.sockfd = -1;
		gettimeofday(&state.last_health_assess, NULL);
		LOG("Client to '%s', interface: %s.", peer_addr_pair, config.ifname);
	} else if ((state.sockfd = resolve_and_connect(peer_addr_pair, &state.peer_addr)) >= 0) {
		reset_state_on_reconnect();
		inet_ntop(state.peer_addr.sa.sa_family, addr_of_sockaddr(&state.peer_addr),
				s_peer_addr, sizeof(s_peer_addr));
		LOG("Client to %s:%u, interface: %s.",
				s_peer_addr, ntohs(port_of_sockaddr(&state.peer_addr)), config.ifname);
	} else {
		LOG("*** Unable to resolve or connect to '%s'.", peer_addr_pair);
		return -1;
	}

	if (config.exit_after)
		LOG("NOTICE: This client will exit autonomously in %u seconds.", config.exit_after);

	if (config.pid_file) {
		FILE *fp;
		if ((fp = fopen(config.pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)getpid());
			fclose(fp);
		}
	}

	signal(SIGUSR1, usr1_signal_handler);

	for (;;) {
		fd_set rset;
		struct timeval __current, timeo;
		int rc;
		bool need_reconnect = false;

		FD_ZERO(&rset);
		FD_SET(state.tunfd, &rset);
		if (state.sockfd >= 0)
			FD_SET(state.sockfd, &rset);

		timeo = (struct timeval) { 0, 500000 };
		rc = select((state.tunfd > state.sockfd ? state.tunfd : state.sockfd) + 1,
				&rset, NULL, NULL, &timeo);
		if (rc < 0) {
			if (errno == EINTR || errno == ERESTART) continue;
            PLOG("*** select() failed");
			return -1;
		}

		gettimeofday(&__current, NULL);

		if (timercmp(&state.last_recv, &__current, >)) state.last_recv = __current;
		if (timercmp(&state.last_echo_sent, &__current, >)) state.last_echo_sent = __current;
		if (timercmp(&state.last_echo_recv, &__current, >)) state.last_echo_recv = __current;

		if (config.exit_after && __sub_timeval_ms(&__current, &startup_time)
				>= config.exit_after * 1000) {
			LOG("User sets a force-to-exit after %u seconds. Exited.", config.exit_after);
			exit(0);
		}

		if (state.sockfd < 0 ||
			(unsigned)__sub_timeval_ms(&__current, &state.last_echo_recv)
				>= config.reconnect_timeo * 1000) {
			need_reconnect = true;
		} else {
			if ((unsigned)__sub_timeval_ms(&__current, &state.last_health_assess)
					>= config.health_assess_interval * 1000) {
				state.last_health_assess = __current;
				if (do_link_health_assess()) {
					if (!state.is_link_ok) {
						if (config.dynamic_link)
							handle_link_up();
						state.is_link_ok = true;
					}
					state.health_based_link_up = false;
				} else {
					need_reconnect = true;
					state.health_based_link_up = true;
				}
			}
		}

		if (rewind_dynamic_link_metric) {
			rewind_dynamic_link_metric = false;
			if (state.is_link_ok) {
				if (config.dynamic_link)
					handle_link_down();
				state.is_link_ok = false;
			}
			state.rt_metric = config.vt_metric;
			LOG("Reset dynamic link route metric.");
			need_reconnect = true;
		}

		if (need_reconnect) {
reconnect:
			if (state.is_link_ok) {
				if (config.dynamic_link)
					handle_link_down();
				state.is_link_ok = false;
			}
			if (state.sockfd >= 0)
				close(state.sockfd);
			if ((state.sockfd = resolve_and_connect(peer_addr_pair, &state.peer_addr)) < 0) {
				LOG("Unable to connect to '%s', retrying.", peer_addr_pair);
				sleep(5);
				goto reconnect;
			}
			reset_state_on_reconnect();
			inet_ntop(state.peer_addr.sa.sa_family, addr_of_sockaddr(&state.peer_addr),
					s_peer_addr, sizeof(s_peer_addr));
			LOG("Reconnected to %s:%u.", s_peer_addr,
					ntohs(port_of_sockaddr(&state.peer_addr)));
			continue;
		}

		if (state.sockfd >= 0 && FD_ISSET(state.sockfd, &rset)) {
			network_receiving(&buffers);
		}

		if (FD_ISSET(state.tunfd, &rset)) {
			tunnel_receiving(&buffers);
		}

		if (state.sockfd >= 0 &&
			(unsigned)__sub_timeval_ms(&__current, &state.last_echo_sent)
				>= config.keepalive_interval * 1000) {
			do_an_echo_request();
			state.last_echo_sent = __current;
		}
	}

    free(buffers.read_buffer);
    free(buffers.crypt_buffer);
    free(buffers.tun_buffer);
    free(state.stats_buckets);

	return 0;
}

#endif /* WITH_CLIENT_MODE */
