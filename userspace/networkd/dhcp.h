/* dhcp.h - minimal DHCPv4 client (RFC 2131) on a packet socket */
#ifndef DHCP_H
#define DHCP_H
#include <stdint.h>
#include <time.h>

enum { DHCP_INIT, DHCP_SELECTING, DHCP_REQUESTING, DHCP_BOUND, DHCP_RENEWING, DHCP_REBINDING };
enum { DHCP_EV_NONE, DHCP_EV_BOUND, DHCP_EV_LOST };

struct dhcp {
	int fd, ifindex, state, tries;
	uint8_t mac[6];
	char host[33];
	uint32_t xid, server, ip, mask, router, dns[2];	/* network byte order */
	uint32_t lease, t1, t2;				/* seconds */
	time_t bound_at, next;
};

int dhcp_start(struct dhcp *d, int ifindex, const uint8_t mac[6], const char *hostname);
void dhcp_stop(struct dhcp *d);
int dhcp_rx(struct dhcp *d);		/* fd readable: DHCP_EV_* */
int dhcp_tick(struct dhcp *d);		/* call at least once a second: DHCP_EV_* */
int dhcp_timeout_ms(const struct dhcp *d);
#endif
