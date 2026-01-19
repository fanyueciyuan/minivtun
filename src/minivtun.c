/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "minivtun.h"
#include "list.h"
#include "log.h"

struct minivtun_config config = {
	.ifname = "",
	.tun_mtu = 1300,
	.tun_qlen = 500, /* driver default */
	.crypto_algo = "aes-128",
	.crypto_passwd = "",
	.pid_file = NULL,
	.in_background = false,
	.tap_mode = false,
#if WITH_CLIENT_MODE
	.wait_dns = false,
	.exit_after = 0,
	.dynamic_link = false,
	.reconnect_timeo = 47,
	.max_droprate = 100,
	.max_rtt = 0,
	.keepalive_interval = 7,
	.health_assess_interval = 60,
	.nr_stats_buckets = 3,
	.health_file = NULL,
	.vt_metric = 0,
	.metric_stepping = 0,
	.vt_table = "",
#endif
};

struct state_variables state = {
	.tunfd = -1,
	.sockfd = -1,
	.crypto_ctx = NULL,
};

static void vt_route_add(short af, void *n, int prefix, void *g)
{
	union {
		struct in_addr in;
#if WITH_IPV6
		struct in6_addr in6;
#endif
	} *network = n, *gateway = g;
	struct vt_route *rt;

	rt = malloc(sizeof(struct vt_route));
    if (!rt) {
        PLOG("malloc for vt_route failed");
        return;
    }
	memset(rt, 0x0, sizeof(*rt));

	rt->af = af;
	rt->prefix = prefix;
	if (af == AF_INET) {
		rt->network.in = network->in;
		rt->network.in.s_addr &= prefix ? htonl(~((1U << (32 - prefix)) - 1)) : 0;
		rt->gateway.in = gateway->in;
	}
#if WITH_IPV6
    else if (af == AF_INET6) {
		int i;
		rt->network.in6 = network->in6;
		if (prefix < 128) {
			rt->network.in6.s6_addr[prefix / 8] &= ~((1 << (8 - prefix % 8)) - 1);
			for (i = prefix / 8 + 1; i < 16; i++)
				rt->network.in6.s6_addr[i] &= 0x00;
		}
		rt->gateway.in6 = gateway->in6;
	}
#endif
    else {
		assert(0);
	}

	/* Append to the list */
	rt->next = config.vt_routes;
	config.vt_routes = rt;
}

static void parse_virtual_route(const char *arg)
{
	char expr[80], *net, *pfx, *gw;
	short af = 0;
	int prefix = -1;
	union {
		struct in_addr in;
#if WITH_IPV6
		struct in6_addr in6;
#endif
	} network, gateway;

	strncpy(expr, arg, sizeof(expr));
	expr[sizeof(expr) - 1] = '\0';

	/* Has gateway or not */
	if ((gw = strchr(expr, '=')))
		*(gw++) = '\0';

	/* Network or single IP/IPv6 address */
	net = expr;
	if ((pfx = strchr(net, '/'))) {
		*(pfx++) = '\0';
		prefix = strtol(pfx, NULL, 10);
		if (errno != ERANGE && prefix >= 0 && prefix <= 32 &&
			inet_pton(AF_INET, net, &network)) {
			af = AF_INET;
		}
#if WITH_IPV6
        else if (errno != ERANGE && prefix >= 0 && prefix <= 128 &&
			inet_pton(AF_INET6, net, &network)) {
			af = AF_INET6;
		}
#endif
        else {
			LOG("*** Not a valid route expression '%s'.", arg);
			exit(1);
		}
	} else {
		if (inet_pton(AF_INET, net, &network)) {
			af = AF_INET;
			prefix = 32;
		}
#if WITH_IPV6
        else if (inet_pton(AF_INET6, net, &network)) {
			af = AF_INET6;
			prefix = 128;
		}
#endif
        else {
			LOG("*** Not a valid route expression '%s'.", arg);
			exit(1);
		}
	}

	/* Has gateway or not */
	if (gw) {
		if (!inet_pton(af, gw, &gateway)) {
			LOG("*** Not a valid route expression '%s'.", arg);
			exit(1);
		}
	} else {
		memset(&gateway, 0x0, sizeof(gateway));
	}

	vt_route_add(af, &network, prefix, &gateway);
}

static void print_help(int argc, char *argv[])
{
	printf("Mini virtual tunneller in non-standard protocol.\n");
	printf("Usage:\n");
	printf("  %s [options]\n", argv[0]);
	printf("Options:\n");
#if WITH_SERVER_MODE
	printf("  -l, --local <ip:port>               local IP:port for server to listen\n");
#endif
#if WITH_CLIENT_MODE
	printf("  -r, --remote <host:port>            host:port of server to connect (brace with [] for bare IPv6)\n");
#endif
	printf("  -n, --ifname <ifname>               virtual interface name\n");
	printf("  -m, --mtu <mtu>                     set MTU size, default: %u.\n", config.tun_mtu);
	printf("  -Q, --qlen <qlen>                   set TX queue length, default: %u\n", config.tun_qlen);
	printf("  -a, --ipv4-addr <tun_lip/pfx>   IPv4 address/prefix length pair\n");
#if WITH_IPV6
	printf("  -A, --ipv6-addr <tun_ip6/pfx>   IPv6 address/prefix length pair\n");
#endif
#if WITH_DAEMONIZE
	printf("  -d, --daemon                        run as daemon process\n");
	printf("  -p, --pidfile <pid_file>            PID file of the daemon\n");
#endif
	printf("  -E, --tap                           TAP mode (L2, ethernet)\n");
	printf("  -e, --key <password>                shared password for data encryption\n");
	printf("  -t, --algo <cipher>                 encryption algorithm (default: %s)\n", config.crypto_algo);
	printf("  -v, --route <net/pfx>[=gw]          attached route on this link, can be multiple\n");
#if WITH_CLIENT_MODE
	printf("  -w, --wait-dns                      wait for DNS resolve ready after service started\n");
	printf("  -D, --dynamic-link                  dynamic link mode, not bring up until data received\n");
	printf("  -M, --metric <metric>[++step]     metric of attached IPv4 routes\n");
	printf("  -T, --table <table_name>            route table of the attached IPv4 routes\n");
	printf("  -x, --exit-after <N>                force the client to exit after N seconds\n");
	printf("  -H, --health-file <path>            file for writing real-time health data\n");
	printf("  -R, --reconnect-timeo <N>           maximum inactive time (seconds) before reconnect, default: %u\n", config.reconnect_timeo);
	printf("  -K, --keepalive <N>                 seconds between keep-alive tests, default: %u\n", config.keepalive_interval);
	printf("  -S, --health-assess <N>             seconds between health assess, default: %u\n", config.health_assess_interval);
	printf("  -B, --stats-buckets <N>             health data buckets, default: %u\n", config.nr_stats_buckets);
	printf("  -P, --max-droprate <1-100>          maximum allowed packet drop percentage, default: %u%%\n", config.max_droprate);
	printf("  -X, --max-rtt <N>                   maximum allowed echo delay (ms), default: unlimited\n");
#endif
	printf("  -h, --help                          print this help\n");
}

int main(int argc, char *argv[])
{
	const char *tun_ip_config = NULL;
#if WITH_IPV6
    const char *tun_ip6_config = NULL;
#endif
	const char *loc_addr_pair = NULL, *peer_addr_pair = NULL;
	int override_mtu = 0, opt;
	struct timeval current;
	char *sp;

	static struct option long_opts[] = {
#if WITH_SERVER_MODE
		{ "local", required_argument, 0, 'l', },
#endif
#if WITH_CLIENT_MODE
		{ "remote", required_argument, 0, 'r', },
#endif
		{ "ipv4-addr", required_argument, 0, 'a', },
#if WITH_IPV6
		{ "ipv6-addr", required_argument, 0, 'A', },
#endif
		{ "ifname", required_argument, 0, 'n', },
		{ "mtu", required_argument, 0, 'm', },
		{ "qlen", required_argument, 0, 'Q', },
#if WITH_DAEMONIZE
		{ "pidfile", required_argument, 0, 'p', },
		{ "daemon", no_argument, 0, 'd', },
#endif
		{ "tap", no_argument, 0, 'E', },
		{ "key", required_argument, 0, 'e', },
		{ "algo", required_argument, 0, 't', },
		{ "route", required_argument, 0, 'v', },
#if WITH_CLIENT_MODE
		{ "wait-dns", no_argument, 0, 'w', },
		{ "exit-after", required_argument, 0, 'x', },
		{ "dynamic-link", no_argument, 0, 'D', },
		{ "reconnect", required_argument, 0, 'R', },
		{ "keepalive", required_argument, 0, 'K', },
		{ "health-assess", required_argument, 0, 'S', },
		{ "stats-buckets", required_argument, 0, 'B', },
		{ "health-file", required_argument, 0, 'H', },
		{ "max-droprate", required_argument, 0, 'P', },
		{ "max-rtt", required_argument, 0, 'X', },
		{ "metric", required_argument, 0, 'M', },
		{ "table", required_argument, 0, 'T', },
#endif
		{ "help", no_argument, 0, 'h', },
		{ 0, 0, 0, 0, },
	};

	while ((opt = getopt_long(argc, argv, "l:r:a:A:m:Q:n:p:e:t:v:x:R:K:S:B:H:P:X:M:T:DEwdh",
			long_opts, NULL)) != -1) {
		switch (opt) {
#if WITH_SERVER_MODE
		case 'l':
			loc_addr_pair = optarg;
			break;
#endif
#if WITH_CLIENT_MODE
		case 'r':
			peer_addr_pair = optarg;
			break;
#endif
		case 'a':
			tun_ip_config = optarg;
			break;
#if WITH_IPV6
		case 'A':
			tun_ip6_config = optarg;
			break;
#endif
		case 'n':
			strncpy(config.ifname, optarg, sizeof(config.ifname) - 1);
			config.ifname[sizeof(config.ifname) - 1] = '\0';
			break;
		case 'm':
			override_mtu = strtoul(optarg, NULL, 10);
			break;
		case 'Q':
			config.tun_qlen = strtoul(optarg, NULL, 10);
			break;
#if WITH_DAEMONIZE
		case 'p':
			config.pid_file = optarg;
			break;
		case 'd':
			config.in_background = true;
			break;
#endif
		case 'E':
			config.tap_mode = true;
			break;
		case 'e':
			config.crypto_passwd = optarg;
			break;
		case 't':
			config.crypto_algo = optarg;
			break;
		case 'v':
			parse_virtual_route(optarg);
			break;
#if WITH_CLIENT_MODE
		case 'w':
			config.wait_dns = true;
			break;
		case 'x':
			config.exit_after = strtoul(optarg, NULL, 10);
			break;
		case 'D':
			config.dynamic_link = true;
			break;
		case 'R':
			config.reconnect_timeo = strtoul(optarg, NULL, 10);
			break;
		case 'K':
			config.keepalive_interval = strtoul(optarg, NULL, 10);
			break;
		case 'S':
			config.health_assess_interval = strtoul(optarg, NULL, 10);
			break;
		case 'B':
			config.nr_stats_buckets = strtoul(optarg, NULL, 10);
			break;
		case 'H':
			config.health_file = optarg;
			break;
		case 'P':
			config.max_droprate = strtoul(optarg, NULL, 10);
			if (config.max_droprate < 1 || config.max_droprate > 100) {
				LOG("*** Acceptable '--max-droprate' values: 1~100.");
				exit(1);
			}
			break;
		case 'X':
			config.max_rtt = strtoul(optarg, NULL, 10);
			break;
		case 'M':
			if ((sp = strstr(optarg, "++"))) {
				char s[16];
				memcpy(s, optarg, sp - optarg);
				s[sp - optarg] = '\0';
				sp += 2;
				config.vt_metric = strtoul(s, NULL, 10);
				config.metric_stepping = strtol(sp, NULL, 10);
			} else {
				config.vt_metric = strtoul(optarg, NULL, 10);
			}
			break;
		case 'T':
			strncpy(config.vt_table, optarg, sizeof(config.vt_table));
			config.vt_table[sizeof(config.vt_table) - 1] = '\0';
			break;
#endif
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
	} else if (config.tap_mode) {
		config.tun_mtu = 1500;
	}

	gettimeofday(&current, NULL);
	srand(current.tv_sec ^ current.tv_usec ^ getpid());

	if (config.ifname[0] == '\0')
		strcpy(config.ifname, "mv%d");
	if ((state.tunfd = plat_tun_alloc(config.ifname, config.tap_mode)) < 0) {
		LOG("*** plat_tun_alloc() failed: %s.", strerror(errno));
		exit(1);
	}

	openlog(config.ifname, LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_USER);

	if (tun_ip_config) {
		char s_lip[20], s_rip[20], *sp;
		struct in_addr vaddr;
		int pfxlen = 0;

		if (!(sp = strchr(tun_ip_config, '/'))) {
			LOG("*** Invalid IPv4 address pair: %s.", tun_ip_config);
			exit(1);
		}
		strncpy(s_lip, tun_ip_config, sp - tun_ip_config);
		s_lip[sp - tun_ip_config] = '\0';
		sp++;
		strncpy(s_rip, sp, sizeof(s_rip));
		s_rip[sizeof(s_rip) - 1] = '\0';

		if (!inet_pton(AF_INET, s_lip, &vaddr)) {
			LOG("*** Invalid local IPv4 address: %s.", s_lip);
			exit(1);
		}
		config.tun_in_local = vaddr;
		if (inet_pton(AF_INET, s_rip, &vaddr)) {
			if (loc_addr_pair) {
				struct in_addr nz = { .s_addr = 0 };
				vt_route_add(AF_INET, &nz, 0, &vaddr);
			}
			config.tun_in_peer = vaddr;
		} else if (sscanf(s_rip, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen < 32 ) {
			config.tun_in_prefix = pfxlen;
		} else {
			LOG("*** Not a legal netmask or prefix length: %s.", s_rip);
			exit(1);
		}
		plat_ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
				&config.tun_in_peer, config.tun_in_prefix);
	}

#if WITH_IPV6
	if (tun_ip6_config) {
		char s_lip[50], s_pfx[20], *sp;
		struct in6_addr vaddr;
		int pfxlen = 0;

		if (!(sp = strchr(tun_ip6_config, '/'))) {
			LOG("*** Invalid IPv6 address pair: %s.", tun_ip6_config);
			exit(1);
		}
		strncpy(s_lip, tun_ip6_config, sp - tun_ip6_config);
		s_lip[sp - tun_ip6_config] = '\0';
		sp++;
		strncpy(s_pfx, sp, sizeof(s_pfx));
		s_pfx[sizeof(s_pfx) - 1] = '\0';

		if (!inet_pton(AF_INET6, s_lip, &vaddr)) {
			LOG("*** Invalid local IPv6 address: %s.", s_lip);
			exit(1);
		}
		config.tun_in6_local = vaddr;
		if (!(sscanf(s_pfx, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen <= 128)) {
			LOG("*** Not a legal prefix length: %s.", s_pfx);
			exit(1);
		}
		config.tun_in6_prefix = pfxlen;

		plat_ip_addr_add_ipv6(config.ifname, &config.tun_in6_local, config.tun_in6_prefix);
	}
#endif

	plat_ip_link_set_mtu(config.ifname, config.tun_mtu);
	plat_ip_link_set_txqueue_len(config.ifname, config.tun_qlen);
	plat_ip_link_set_updown(config.ifname, true);

	if (enabled_encryption()) {
        const void* cptype = crypto_get_type(config.crypto_algo);
		if (cptype == NULL) {
			LOG("*** No such encryption type defined: %s.", config.crypto_algo);
			exit(1);
		}
        state.crypto_ctx = crypto_init(cptype, config.crypto_passwd);
        if (state.crypto_ctx == NULL) {
            LOG("*** Failed to initialize crypto context.");
            exit(1);
        }
	} else {
		LOG("*** WARNING: Transmission will not be encrypted.");
	}

#if WITH_DAEMONIZE
    if(config.in_background) {
        plat_daemonize();
    }
#endif

#if WITH_SERVER_MODE
	if (loc_addr_pair) {
		run_server(loc_addr_pair);
	} else
#endif
#if WITH_CLIENT_MODE
    if (peer_addr_pair) {
		run_client(peer_addr_pair);
	} else
#endif
    {
		LOG("*** No valid local or peer address specified.");
		exit(1);
	}

	/* Some cleanups before exit */
#if WITH_CLIENT_MODE
	if (config.health_file)
		remove(config.health_file);
#endif
    crypto_free(state.crypto_ctx);
	closelog();

	return 0;
}

