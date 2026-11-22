/*
 * dhcp.c - minimal DHCPv4 client: DISCOVER / OFFER / REQUEST / ACK, NAK, renew at T1,
 * rebind at T2, lease expiry.  Raw IPv4/UDP on an AF_PACKET (SOCK_DGRAM) socket, so it works
 * before the interface has an address; replies are taken from it whatever their destination.
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "dhcp.h"

#define BOOTP_LEN	236
#define MAGIC		0x63825363u

static time_t now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec;
}

#define MAX_LEASE	(30u * 86400u)

static uint16_t csum(const uint8_t *p, int len)
{
	uint32_t s = 0;
	int i;

	for (i = 0; i + 1 < len; i += 2)
		s += (uint32_t)(p[i] << 8 | p[i + 1]);
	if (len & 1)
		s += (uint32_t)p[len - 1] << 8;
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	return (uint16_t)~s;
}

static int opt(uint8_t *o, int n, int code, const void *d, int len)
{
	o[n] = (uint8_t)code;
	o[n + 1] = (uint8_t)len;
	memcpy(o + n + 2, d, (size_t)len);
	return n + 2 + len;
}

static int send_msg(struct dhcp *d, int type)
{
	uint8_t pkt[28 + BOOTP_LEN + 312], *ip = pkt, *udp = pkt + 20, *b = pkt + 28, *o = b + BOOTP_LEN;
	struct sockaddr_ll ll;
	uint32_t magic = htonl(MAGIC);
	uint8_t t = (uint8_t)type, cid[7], prl[] = { 1, 3, 6, 15, 51, 54, 58, 59 };
	int n = 0, len;

	memset(pkt, 0, sizeof(pkt));
	b[0] = 1; b[1] = 1; b[2] = 6;				/* BOOTREQUEST, ethernet */
	memcpy(b + 4, &d->xid, 4);
	if (d->state == DHCP_RENEWING || d->state == DHCP_REBINDING)
		memcpy(b + 12, &d->ip, 4);			/* ciaddr */
	else
		b[10] = 0x80;					/* broadcast reply wanted */
	memcpy(b + 28, d->mac, 6);
	memcpy(o, &magic, 4); n = 4;
	n = opt(o, n, 53, &t, 1);
	cid[0] = 1; memcpy(cid + 1, d->mac, 6);
	n = opt(o, n, 61, cid, 7);
	if (type == 3 && d->state == DHCP_REQUESTING) {
		n = opt(o, n, 50, &d->ip, 4);
		n = opt(o, n, 54, &d->server, 4);
	}
	if (d->host[0])
		n = opt(o, n, 12, d->host, (int)strlen(d->host));
	n = opt(o, n, 55, prl, sizeof(prl));
	o[n++] = 255;
	len = 28 + BOOTP_LEN + n;
	if (len < 28 + 300)
		len = 28 + 300;					/* minimum BOOTP size */
	ip[0] = 0x45; ip[2] = (uint8_t)(len >> 8); ip[3] = (uint8_t)len; ip[8] = 64; ip[9] = 17;
	memset(ip + 16, 0xFF, 4);					/* src 0.0.0.0, dst 255.255.255.255 */
	{ uint16_t c = csum(ip, 20); ip[10] = (uint8_t)(c >> 8); ip[11] = (uint8_t)c; }
	udp[1] = 68; udp[3] = 67;
	udp[4] = (uint8_t)((len - 20) >> 8); udp[5] = (uint8_t)(len - 20);	/* UDP checksum 0 = none */
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = htons(ETH_P_IP);
	ll.sll_ifindex = d->ifindex;
	ll.sll_halen = 6;
	memset(ll.sll_addr, 0xFF, 6);
	return sendto(d->fd, pkt, (size_t)len, 0, (struct sockaddr *)&ll, sizeof(ll)) < 0 ? -1 : 0;
}

static void schedule(struct dhcp *d)
{
	int w = 4 << (d->tries < 3 ? d->tries : 3);			/* 4, 8, 16, 32 s */

	d->next = now() + w;
	d->tries++;
}

static void restart(struct dhcp *d)
{
	d->state = DHCP_SELECTING;
	d->tries = 0;
	d->xid = (uint32_t)now() ^ (uint32_t)(d->mac[5] << 24 | d->mac[4] << 16 | d->mac[3] << 8 | d->mac[2]);
	send_msg(d, 1);						/* DISCOVER */
	schedule(d);
}

int dhcp_start(struct dhcp *d, int ifindex, const uint8_t mac[6], const char *hostname)
{
	struct sockaddr_ll ll;

	memset(d, 0, sizeof(*d));
	d->ifindex = ifindex;
	memcpy(d->mac, mac, 6);
	strncpy(d->host, hostname ? hostname : "", sizeof(d->host) - 1);
	d->fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
	if (d->fd < 0)
		return -1;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = htons(ETH_P_IP);
	ll.sll_ifindex = ifindex;
	if (bind(d->fd, (struct sockaddr *)&ll, sizeof(ll))) {
		close(d->fd);
		d->fd = -1;
		return -1;
	}
	restart(d);
	return 0;
}

void dhcp_stop(struct dhcp *d)
{
	if (d->fd > 0)
		close(d->fd);
	d->fd = -1;
}

int dhcp_rx(struct dhcp *d)
{
	uint8_t p[1600], type = 0;
	uint32_t server = 0, mask = 0, router = 0, dns[2] = { 0, 0 }, lease = 0, t1 = 0, t2 = 0, magic;
	const uint8_t *b, *o, *end;
	int n = (int)recv(d->fd, p, sizeof(p), MSG_DONTWAIT), ihl;

	if (n < 28 || (p[0] >> 4) != 4 || p[9] != 17)
		return DHCP_EV_NONE;
	ihl = (p[0] & 15) * 4;
	if (n < ihl + 8 + BOOTP_LEN + 4 || p[ihl + 2] != 0 || p[ihl + 3] != 68)
		return DHCP_EV_NONE;
	b = p + ihl + 8;
	memcpy(&magic, b + BOOTP_LEN, 4);
	if (b[0] != 2 || memcmp(b + 4, &d->xid, 4) || memcmp(b + 28, d->mac, 6) || magic != htonl(MAGIC))
		return DHCP_EV_NONE;
	for (o = b + BOOTP_LEN + 4, end = p + n; o + 2 <= end && *o != 255;) {
		int c = o[0], l;

		if (c == 0) { o++; continue; }
		l = o[1];
		if (o + 2 + l > end)
			break;
		if (c == 53 && l == 1) type = o[2];
		if (c == 54 && l == 4) memcpy(&server, o + 2, 4);
		if (c == 1 && l == 4) memcpy(&mask, o + 2, 4);
		if (c == 3 && l >= 4) memcpy(&router, o + 2, 4);
		if (c == 6 && l >= 4) memcpy(&dns[0], o + 2, 4);
		if (c == 6 && l >= 8) memcpy(&dns[1], o + 6, 4);
		if (c == 51 && l == 4) lease = ntohl(*(const uint32_t *)(o + 2));
		if (c == 58 && l == 4) t1 = ntohl(*(const uint32_t *)(o + 2));
		if (c == 59 && l == 4) t2 = ntohl(*(const uint32_t *)(o + 2));
		o += 2 + l;
	}
	if (type == 2 && d->state == DHCP_SELECTING) {			/* OFFER */
		memcpy(&d->ip, b + 16, 4);
		d->server = server;
		d->state = DHCP_REQUESTING;
		d->tries = 0;
		send_msg(d, 3);
		schedule(d);
		return DHCP_EV_NONE;
	}
	if (type == 5 && d->state >= DHCP_REQUESTING) {			/* ACK */
		memcpy(&d->ip, b + 16, 4);
		if (server) d->server = server;
		d->mask = mask ? mask : htonl(0xFFFFFF00u);
		d->router = router;
		d->dns[0] = dns[0]; d->dns[1] = dns[1];
		/* the server's numbers are not trusted: an infinite lease (0xFFFFFFFF) or huge T1/T2 would
		 * overflow the time arithmetic below and in the poll timeout; renew at least monthly */
		if (lease > MAX_LEASE)
			lease = MAX_LEASE;
		d->lease = lease ? lease : 3600;
		d->t1 = t1 ? t1 : d->lease / 2;
		d->t2 = t2 ? t2 : (uint32_t)((uint64_t)d->lease * 7 / 8);
		if (d->t1 > d->lease)
			d->t1 = d->lease;
		if (d->t2 > d->lease)
			d->t2 = d->lease;
		d->bound_at = now();
		d->state = DHCP_BOUND;
		d->next = d->bound_at + d->t1;
		return DHCP_EV_BOUND;
	}
	if (type == 6 && d->state >= DHCP_REQUESTING) {			/* NAK */
		int was = d->state >= DHCP_BOUND;
		restart(d);
		return was ? DHCP_EV_LOST : DHCP_EV_NONE;
	}
	return DHCP_EV_NONE;
}

int dhcp_tick(struct dhcp *d)
{
	time_t t = now();

	if (t < d->next)
		return DHCP_EV_NONE;
	switch (d->state) {
	case DHCP_SELECTING:
		send_msg(d, 1);
		schedule(d);
		break;
	case DHCP_REQUESTING:
		if (d->tries >= 4) {
			restart(d);
			break;
		}
		send_msg(d, 3);
		schedule(d);
		break;
	case DHCP_BOUND:
		d->state = DHCP_RENEWING;
		d->tries = 0;
		/* fall through */
	case DHCP_RENEWING:
	case DHCP_REBINDING:
		if (t >= d->bound_at + (time_t)d->lease) {
			restart(d);
			return DHCP_EV_LOST;
		}
		if (t >= d->bound_at + (time_t)d->t2)
			d->state = DHCP_REBINDING;
		send_msg(d, 3);
		d->next = t + 30;
		break;
	}
	return DHCP_EV_NONE;
}

int dhcp_timeout_ms(const struct dhcp *d)
{
	time_t t = now();

	if (d->next <= t)
		return 0;
	return d->next - t > 60 ? 60000 : (int)(d->next - t) * 1000;	/* a minute at most: no int overflow */
}
