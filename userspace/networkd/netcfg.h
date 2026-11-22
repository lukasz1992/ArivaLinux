/* netcfg.h - interface, address, default route and resolv.conf by ioctl (IPv4) */
#ifndef NETCFG_H
#define NETCFG_H
#include <stdint.h>

int nc_index(const char *ifn);
int nc_up(const char *ifn);
int nc_hwaddr(const char *ifn, uint8_t mac[6]);
int nc_carrier(const char *ifn);
int nc_addr(const char *ifn, uint32_t ip, uint32_t mask);	/* ip 0: remove the address */
int nc_route(const char *ifn, uint32_t gw);			/* replace the default route; 0: remove */
int nc_resolv(const uint32_t *dns, int n);
void nc_ipstr(uint32_t a, char *s);				/* network byte order */
int nc_link_open(void);					/* rtnetlink, link events (hot-plug, carrier) */
void nc_link_drain(int fd);
#endif
