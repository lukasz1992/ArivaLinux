/* nl.h - minimal nl80211 client (generic netlink, no libnl) for a station interface */
#ifndef NL_H
#define NL_H
#include <stdint.h>

struct nl {
	int fd, ev;		/* request socket, event socket (groups "scan", "mlme") */
	int family;		/* nl80211 generic netlink family id */
	uint32_t seq;
	uint8_t bssid[6];	/* AP of the last CONNECT event */
};

struct bss {
	uint8_t bssid[6];
	uint32_t freq;
	int signal_mbm;
	char ssid[33];
	int privacy, rsn_ok, akm, mfpc, mfpr;
};

enum { NL_EV_NONE, NL_EV_SCAN_DONE, NL_EV_SCAN_ABORTED, NL_EV_CONNECT, NL_EV_DISCONNECT,
       NL_EV_CQM_LOW, NL_EV_CQM_HIGH, NL_EV_BEACON_LOSS };

struct sta {				/* GET_STATION of the AP we are associated with */
	int signal, signal_avg;		/* dBm */
	int tx_rate;			/* 100 kbit/s */
	uint32_t rx_bytes, tx_bytes, connected_time, tx_failed, tx_retries;
};

int nl_open(struct nl *n);
int nl_trigger_scan(struct nl *n, int ifindex, const char *const *ssids, int nssid);
int nl_get_scan(struct nl *n, int ifindex, struct bss *out, int max);
/* bssid NULL: cfg80211's SME picks the AP of the SSID; set: that AP (roaming) */
int nl_connect(struct nl *n, int ifindex, const char *ssid, const uint8_t *bssid, uint32_t freq,
	       const uint8_t *ie, int ie_len, int akm, int mfp);
int nl_disconnect(struct nl *n, int ifindex);
int nl_new_key(struct nl *n, int ifindex, int idx, uint32_t cipher, const uint8_t *key, int klen,
	       const uint8_t *seq, int seqlen, const uint8_t *mac);
int nl_authorize(struct nl *n, int ifindex, const uint8_t *bssid);
int nl_set_cqm(struct nl *n, int ifindex, int thold_dbm, int hyst_db);
int nl_get_station(struct nl *n, int ifindex, const uint8_t *mac, struct sta *s);
/* read one event from n->ev; *status = connect status code / disconnect reason */
int nl_event(struct nl *n, int *status);
#endif
