/* netcfg.c - IPv4 interface configuration by ioctl (no busybox); rtnetlink only for link events */
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "netcfg.h"

static int sock(void)
{
	static int fd = -1;

	if (fd < 0)
		fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	return fd;
}

static void set_ifr(struct ifreq *r, const char *ifn)
{
	memset(r, 0, sizeof(*r));
	strncpy(r->ifr_name, ifn, IFNAMSIZ - 1);
}

static void set_sin(struct sockaddr *sa, uint32_t a)
{
	struct sockaddr_in *s = (struct sockaddr_in *)sa;

	memset(s, 0, sizeof(*s));
	s->sin_family = AF_INET;
	s->sin_addr.s_addr = a;
}

int nc_index(const char *ifn) { return (int)if_nametoindex(ifn); }

int nc_up(const char *ifn)
{
	struct ifreq r;

	set_ifr(&r, ifn);
	if (ioctl(sock(), SIOCGIFFLAGS, &r))
		return -1;
	r.ifr_flags |= IFF_UP;
	return ioctl(sock(), SIOCSIFFLAGS, &r);
}

int nc_hwaddr(const char *ifn, uint8_t mac[6])
{
	struct ifreq r;

	set_ifr(&r, ifn);
	if (ioctl(sock(), SIOCGIFHWADDR, &r))
		return -1;
	memcpy(mac, r.ifr_hwaddr.sa_data, 6);
	return 0;
}

int nc_carrier(const char *ifn)
{
	char p[64], v = '0';
	int fd;

	snprintf(p, sizeof(p), "/sys/class/net/%s/carrier", ifn);
	if ((fd = open(p, O_RDONLY)) >= 0) {
		if (read(fd, &v, 1) != 1)
			v = '0';
		close(fd);
	}
	return v == '1';
}

int nc_addr(const char *ifn, uint32_t ip, uint32_t mask)
{
	struct ifreq r;

	set_ifr(&r, ifn);
	set_sin(&r.ifr_addr, ip);
	if (ioctl(sock(), SIOCSIFADDR, &r))		/* 0.0.0.0 removes it */
		return -1;
	if (!ip)
		return 0;
	set_ifr(&r, ifn);
	set_sin(&r.ifr_netmask, mask);
	return ioctl(sock(), SIOCSIFNETMASK, &r);
}

int nc_route(const char *ifn, uint32_t gw)
{
	struct rtentry rt;
	char dev[IFNAMSIZ];

	snprintf(dev, sizeof(dev), "%s", ifn);
	memset(&rt, 0, sizeof(rt));
	set_sin(&rt.rt_dst, 0);
	set_sin(&rt.rt_genmask, 0);
	rt.rt_dev = dev;
	while (ioctl(sock(), SIOCDELRT, &rt) == 0)	/* drop any default route */
		;
	if (!gw)
		return 0;
	set_sin(&rt.rt_gateway, gw);
	rt.rt_flags = RTF_UP | RTF_GATEWAY;
	return ioctl(sock(), SIOCADDRT, &rt);
}

void nc_ipstr(uint32_t a, char *s)
{
	const uint8_t *b = (const uint8_t *)&a;

	sprintf(s, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

int nc_resolv(const uint32_t *dns, int n)
{
	FILE *f;
	char s[16];
	int i;

	mkdir("/etc", 0755);
	if (!(f = fopen("/etc/resolv.conf.tmp", "w")))
		return -1;
	for (i = 0; i < n; i++)
		if (dns[i]) {
			nc_ipstr(dns[i], s);
			fprintf(f, "nameserver %s\n", s);
		}
	fclose(f);
	return rename("/etc/resolv.conf.tmp", "/etc/resolv.conf");
}

int nc_link_open(void)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK };
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);

	if (fd >= 0 && bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		close(fd);
		fd = -1;
	}
	return fd;
}

/* the events only wake the main loop; the state is re-read from the interfaces themselves */
void nc_link_drain(int fd)
{
	char b[4096];

	while (recv(fd, b, sizeof(b), MSG_DONTWAIT) > 0)
		;
}
