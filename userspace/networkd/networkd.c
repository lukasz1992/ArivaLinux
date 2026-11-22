/*
 * networkd - network manager for the Ferguson Ariva 54 (ALi C3503D) Linux port.  One process,
 * no busybox: reads the receiver's own settings (SYSTEM_DATA record in the last 64 KiB of the
 * "userdb" partition, docs/research/a54_settings.md), keeps the saved Wi-Fi networks (as many as
 * the original firmware: 3, in their stored order), and brings the network up:
 *   - interface: eth0 with a cable, else wlan0, else eth0 without a cable; both are watched all the
 *     time (rtnetlink link events + a 1 s check): eth0 is there from boot or never, wlan0 (USB) comes
 *     and goes. Switch over when wlan0 appears/disappears or the cable is (un)plugged; never exits;
 *   - Wi-Fi (nl80211, cfg80211 SME): scan, first saved network in range, Open or WPA2-PSK/CCMP
 *     (optional MFP), own supplicant (wpa.c), GTK rekey, reconnect after a disconnect;
 *   - address: own DHCP client (dhcp.c) or the static settings; ioctl (netcfg.c), resolv.conf.
 * WEP, TKIP and WPA1 are not supported (such saved networks are skipped).
 *
 * networkd [-f FILE] [-o OFFSET] [-i IF] [-p] [-s]
 *   -f/-o  settings source (default /dev/mtd7 @0xF0000; a whole .abs: -o 0x7F0000)
 *   -i     force the interface (waits for it)   -p  print the settings and exit   -s  show secrets when printing
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "dhcp.h"
#include "netcfg.h"
#include "nl.h"
#include "wpa.h"

#define SECTOR		0x10000
#define REC_START	0x12345678u
#define REC_END		0x87654321u
#define MAX_AP		3			/* as the original firmware */
#define ENC_NONE	0
#define ENC_WPA2_AES	6
#define ENC_WPA2_MIXED	8			/* WPA2PSK_TKIPAES: we use CCMP */

struct ap { char ssid[33]; uint32_t enc; char key[137]; uint8_t pmk[32]; };
struct cfg {
	unsigned n;
	int use_last, dhcp;
	uint32_t ip, mask, gw, dns[2];		/* network byte order */
	char name[33];
	int n_ap;
	struct ap ap[MAX_AP];
};

static int show;

static const char *enc_name(uint32_t e)
{
	static const char *n[] = { "NONE", "OPEN_WEP", "SHARED_WEP", "WPAPSK_TKIP", "WPAPSK_AES",
				   "WPA2PSK_TKIP", "WPA2PSK_AES", "WPAPSK_TKIPAES", "WPA2PSK_TKIPAES" };
	return e < sizeof(n) / sizeof(n[0]) ? n[e] : "?";
}

static int supported(uint32_t e) { return e == ENC_NONE || e == ENC_WPA2_AES || e == ENC_WPA2_MIXED; }

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

static void cstr(char *dst, const uint8_t *src, size_t max)
{
	size_t i;

	for (i = 0; i < max && src[i]; i++)
		dst[i] = (char)src[i];
	dst[i] = 0;
}

static int load(const char *file, long off, struct cfg *c)
{
	static uint8_t s[SECTOR];
	static const unsigned sizes[] = { 5356, 5372, 5380 };
	const uint8_t *d = NULL;
	unsigned o = 0, k, wifi;
	int fd = open(file, O_RDONLY);

	if (fd < 0 || pread(fd, s, SECTOR, off) != SECTOR) {
		fprintf(stderr, "networkd: cannot read %s @0x%lx: %s\n", file, off, strerror(errno));
		return -1;
	}
	close(fd);
	memset(c, 0, sizeof(*c));
	while (o + 8 < SECTOR && le32(s + o) == REC_START) {	/* the newest complete record */
		for (k = 0; k < 3; k++)
			if (o + 8 + sizes[k] <= SECTOR && le32(s + o + 4 + sizes[k]) == REC_END)
				break;
		if (k == 3)
			break;
		c->n = sizes[k];
		d = s + o + 4;
		o += sizes[k] + 8;
	}
	if (!d) {
		fprintf(stderr, "networkd: no settings record: DHCP, no Wi-Fi networks\n");
		c->dhcp = 1;
		return 0;
	}
	/* IP_CFG (SDK system_data.h) at 0xFE0 in every build, fields in memory = network order */
	c->use_last = d[0xFE0] & 1;
	c->dhcp = le32(d + 0xFE4) != 0 || !c->use_last;
	memcpy(&c->ip, d + 0xFE8, 4);
	memcpy(&c->mask, d + 0xFEC, 4);
	memcpy(&c->gw, d + 0xFF0, 4);
	memcpy(&c->dns[0], d + 0xFF4, 4);
	memcpy(&c->dns[1], d + 0xFF8, 4);
	/* vendor fields after 0x109C sit 0x10 lower in the 5356 build (no mgcamd flags) */
	cstr(c->name, d + (c->n == 5356 ? 0x1092 : 0x10A2), 32);
	wifi = c->n == 5356 ? 0x1250 : 0x1260;
	c->n_ap = le32(d + wifi) & 0xF;
	if (c->n_ap > MAX_AP)
		c->n_ap = 0;				/* firmware: bad header -> list cleared */
	for (k = 0; k < (unsigned)c->n_ap; k++) {
		const uint8_t *e = d + wifi + 4 + 0xB4 * k;	/* wifi_ap_info: ssid[32] enc u32 key_idx pwd[136] */

		cstr(c->ap[k].ssid, e, 32);
		c->ap[k].enc = le32(e + 0x20);
		cstr(c->ap[k].key, e + 0x25, 136);
	}
	return 0;
}

static void print_cfg(const struct cfg *c)
{
	char a[4][16];
	int i;

	nc_ipstr(c->ip, a[0]); nc_ipstr(c->mask, a[1]); nc_ipstr(c->gw, a[2]); nc_ipstr(c->dns[0], a[3]);
	printf("settings: N=%u, STB name \"%s\", %s", c->n, c->name, c->dhcp ? "DHCP\n" : "static ");
	if (!c->dhcp)
		printf("%s/%s gw %s dns %s\n", show ? a[0] : "*", show ? a[1] : "*", show ? a[2] : "*", show ? a[3] : "*");
	printf("wifi networks: %d\n", c->n_ap);
	for (i = 0; i < c->n_ap; i++)
		printf("  %d: \"%s\" %s key %s%s\n", i + 1, show ? c->ap[i].ssid : "*", enc_name(c->ap[i].enc),
		       show ? c->ap[i].key : (c->ap[i].key[0] ? "*" : "-"), supported(c->ap[i].enc) ? "" : " (unsupported, skipped)");
	fflush(stdout);
}

static int urandom(uint8_t *b, size_t n)
{
	int fd = open("/dev/urandom", O_RDONLY);
	ssize_t r = fd < 0 ? -1 : read(fd, b, n);

	if (fd >= 0)
		close(fd);
	return r == (ssize_t)n ? 0 : -1;
}

static time_t mono(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec;
}

/* ---- state ---- */
enum { S_LINK, S_SCAN, S_CONNECT, S_HANDSHAKE, S_UP, S_WAIT, S_NONE };
static const char *const sname[] = { "link", "scan", "connect", "handshake", "up", "wait", "none" };

static struct {
	struct cfg c;
	const char *ifn;		/* NULL: no interface (waiting for a hot-plug) */
	const char *force;		/* -i */
	int ifindex, wifi, state;
	int nl_ok;			/* nl80211 sockets open (once, on the first Wi-Fi interface) */
	int pmk_ok;			/* PMKs of the saved networks computed (once, likewise) */
	time_t retry_at;		/* attach failed: try again after this */
	time_t deadline;
	uint8_t mac[6];
	struct nl nl;
	int eapol;
	int cur;			/* index of the network being tried */
	struct bss bss;
	struct wpa wpa;
	struct dhcp dhcp;
	int dhcp_on;
	int roam;			/* a background scan for a better AP of the same network */
	int roam_to;			/* connect to st.bss.bssid (roaming target) */
	time_t status_at;
	char last[64];			/* last event, for the status file */
} st;

#define STATUS_FILE	"/run/networkd.status"
#define CQM_THOLD	-75		/* dBm: below it look for a better AP */
#define CQM_HYST	4
#define ROAM_GAIN	8		/* dB better than the current AP to move */

static void event(const char *fmt, const char *arg)
{
	snprintf(st.last, sizeof(st.last), fmt, arg);
	printf("%s\n", st.last);
	fflush(stdout);
	st.status_at = 0;		/* rewrite the status file now */
}

/* key=value snapshot for other processes (cat /run/networkd.status); written atomically */
static void status_write(void)
{
	static const char *const nm[] = { "link", "scan", "connect", "handshake", "up", "wait", "none" };
	char a[16], m[16], g[16], d0[16], d1[16];
	uint32_t ip = st.c.dhcp ? st.dhcp.ip : st.c.ip, mask = st.c.dhcp ? st.dhcp.mask : st.c.mask;
	uint32_t gw = st.c.dhcp ? st.dhcp.router : st.c.gw;
	const uint32_t *dns = st.c.dhcp ? st.dhcp.dns : st.c.dns;
	int up = st.state == S_UP && (!st.c.dhcp || (st.dhcp_on && st.dhcp.state >= DHCP_BOUND));
	FILE *f;

	mkdir("/run", 0755);
	if (!(f = fopen(STATUS_FILE ".tmp", "w")))
		return;
	fprintf(f, "state=%s\ninterface=%s\nip_up=%d\naddress=%s\n", nm[st.state], st.ifn ? st.ifn : "none", up, st.c.dhcp ? "dhcp" : "static");
	if (up) {
		nc_ipstr(ip, a); nc_ipstr(mask, m); nc_ipstr(gw, g); nc_ipstr(dns[0], d0); nc_ipstr(dns[1], d1);
		fprintf(f, "ip=%s\nnetmask=%s\ngateway=%s\ndns=%s %s\n", a, m, g, d0, d1);
		if (st.c.dhcp)
			fprintf(f, "lease=%u\nlease_left=%ld\n", st.dhcp.lease,
				(long)(st.dhcp.bound_at + (time_t)st.dhcp.lease - mono()));
	}
	if (st.wifi) {
		if (st.state >= S_CONNECT && st.state <= S_UP) {
			const uint8_t *b = st.bss.bssid;
			struct sta s;

			fprintf(f, "ssid=%s\nbssid=%02x:%02x:%02x:%02x:%02x:%02x\nfreq=%u\nsecurity=%s%s\n", st.bss.ssid,
				b[0], b[1], b[2], b[3], b[4], b[5], st.bss.freq,
				st.c.ap[st.cur].enc == ENC_NONE ? "open" : "wpa2-psk-ccmp", st.wpa.mfp ? "+mfp" : "");
			if (st.state == S_UP && !nl_get_station(&st.nl, st.ifindex, st.bss.bssid, &s))
				fprintf(f, "signal=%d\nsignal_avg=%d\ntx_rate=%d.%d\nrx_bytes=%u\ntx_bytes=%u\n"
					   "tx_retries=%u\ntx_failed=%u\nconnected_time=%u\n",
					s.signal, s.signal_avg, s.tx_rate / 10, s.tx_rate % 10, s.rx_bytes, s.tx_bytes,
					s.tx_retries, s.tx_failed, s.connected_time);
		}
	}
	fprintf(f, "last_event=%s\n", st.last);
	fclose(f);
	rename(STATUS_FILE ".tmp", STATUS_FILE);
	st.status_at = mono();
}

static void go(int s, int secs)
{
	if (st.state != s) {
		printf("state: %s -> %s\n", sname[st.state], sname[s]);
		st.status_at = 0;
	}
	st.state = s;
	st.deadline = mono() + secs;
	fflush(stdout);
}

static void addr_down(void)
{
	if (st.dhcp_on)
		dhcp_stop(&st.dhcp);
	st.dhcp_on = 0;
	nc_route(st.ifn, 0);
	nc_addr(st.ifn, 0, 0);
}

static void addr_up(void)
{
	char a[16], m[16], g[16];

	if (st.dhcp_on) {			/* never leak the previous DHCP socket */
		dhcp_stop(&st.dhcp);
		st.dhcp_on = 0;
	}

	if (!st.c.dhcp) {
		nc_addr(st.ifn, st.c.ip, st.c.mask);
		nc_route(st.ifn, st.c.gw);
		nc_resolv(st.c.dns, 2);
		nc_ipstr(st.c.ip, a); nc_ipstr(st.c.mask, m); nc_ipstr(st.c.gw, g);
		printf("ip: static %s/%s gw %s\n", show ? a : "*", show ? m : "*", show ? g : "*");
		return;
	}
	if (dhcp_start(&st.dhcp, st.ifindex, st.mac, st.c.name) == 0)
		st.dhcp_on = 1;
	else
		fprintf(stderr, "networkd: dhcp: %s\n", strerror(errno));
}

static void dhcp_event(int ev)
{
	char a[16], m[16], g[16];

	if (ev == DHCP_EV_BOUND) {
		nc_addr(st.ifn, st.dhcp.ip, st.dhcp.mask);
		nc_route(st.ifn, st.dhcp.router);
		nc_resolv(st.dhcp.dns, 2);
		nc_ipstr(st.dhcp.ip, a); nc_ipstr(st.dhcp.mask, m); nc_ipstr(st.dhcp.router, g);
		printf("dhcp: %s/%s gw %s, lease %u s\n", a, m, g, st.dhcp.lease);
	} else if (ev == DHCP_EV_LOST) {
		printf("dhcp: lease lost\n");
		nc_route(st.ifn, 0);
		nc_addr(st.ifn, 0, 0);
	}
	fflush(stdout);
}

/* ---- Wi-Fi ---- */
static int eapol_open(void)
{
	struct sockaddr_ll ll;
	int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_PAE));

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = htons(ETH_P_PAE);
	ll.sll_ifindex = st.ifindex;
	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)&ll, sizeof(ll))) {
		close(fd);
		return -1;
	}
	return fd;
}

static void eapol_send(const uint8_t *f, int len)
{
	struct sockaddr_ll ll;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = htons(ETH_P_PAE);
	ll.sll_ifindex = st.ifindex;
	ll.sll_halen = 6;
	memcpy(ll.sll_addr, st.bss.bssid, 6);
	sendto(st.eapol, f, (size_t)len, 0, (struct sockaddr *)&ll, sizeof(ll));
}

static void wifi_scan(void)
{
	const char *ss[MAX_AP];
	int i, n = 0;

	for (i = 0; i < st.c.n_ap; i++)
		if (supported(st.c.ap[i].enc))
			ss[n++] = st.c.ap[i].ssid;
	if (!n) {
		printf("wifi: no supported saved network\n");
		go(S_WAIT, 3600);
		return;
	}
	if (nl_trigger_scan(&st.nl, st.ifindex, ss, n))
		printf("wifi: scan request failed\n");
	go(S_SCAN, 10);
}

/* after the scan: the first saved network (in the stored order) in range, best signal */
static void wifi_pick(void)
{
	static struct bss list[64];
	int n = nl_get_scan(&st.nl, st.ifindex, list, 64), i, j, best;

	printf("wifi: %d networks in range\n", n < 0 ? 0 : n);
	for (i = 0; i < st.c.n_ap; i++) {
		const struct ap *a = &st.c.ap[i];

		if (!supported(a->enc))
			continue;
		for (best = -1, j = 0; j < n; j++) {
			if (strcmp(list[j].ssid, a->ssid))
				continue;
			if (a->enc == ENC_NONE ? list[j].privacy : !list[j].rsn_ok)
				continue;		/* security does not match / no CCMP-PSK */
			if (best < 0 || list[j].signal_mbm > list[best].signal_mbm)
				best = j;
		}
		if (best < 0)
			continue;
		st.cur = i;
		if (!st.roam_to)
			st.bss = list[best];		/* security parameters; the AP itself is cfg80211's choice */
		memset(&st.wpa, 0, sizeof(st.wpa));
		if (a->enc != ENC_NONE) {
			int mfp = st.bss.mfpc;			/* MFP when the AP offers it */

			memcpy(st.wpa.pmk, a->pmk, 32);
			memcpy(st.wpa.spa, st.mac, 6);
			st.wpa.akm = st.bss.akm;
			st.wpa.mfp = mfp;
			st.wpa.ie_len = wpa_rsn_ie(st.wpa.ie, st.bss.akm, mfp, 0);
		}
		printf("wifi: connecting to \"%s\" (%s%s)%s\n", show ? a->ssid : "*",
		       a->enc == ENC_NONE ? "open" : "WPA2-PSK/CCMP", st.wpa.mfp ? ", MFP" : "", st.roam_to ? ", roaming" : "");
		if (nl_connect(&st.nl, st.ifindex, a->ssid, st.roam_to ? st.bss.bssid : NULL, st.bss.freq,
			       st.wpa.ie, st.wpa.ie_len, st.wpa.akm, st.wpa.mfp)) {
			printf("wifi: connect request failed\n");
			continue;
		}
		go(S_CONNECT, 15);
		return;
	}
	printf("wifi: no saved network in range\n");
	go(S_WAIT, 10);
}

static void wifi_keys(const struct wpa_keys *k, int done)
{
	if ((done & WPA_PTK) && nl_new_key(&st.nl, st.ifindex, 0, WPA_CIPHER_CCMP, k->tk, 16, NULL, 0, st.bss.bssid))
		printf("wifi: pairwise key install failed\n");
	if ((done & WPA_GTK) && k->gtk_len == 16 &&
	    nl_new_key(&st.nl, st.ifindex, k->gtk_idx, WPA_CIPHER_CCMP, k->gtk, 16, k->gtk_rsc, 6, NULL))
		printf("wifi: group key install failed\n");
	if ((done & WPA_GTK) && k->have_igtk && st.wpa.mfp &&
	    nl_new_key(&st.nl, st.ifindex, k->igtk_idx, WPA_CIPHER_BIP, k->igtk, 16, k->ipn, 6, NULL))
		printf("wifi: IGTK install failed\n");
}

/* connected: link quality monitor (CQM: RSSI threshold, beacon loss) */
static void wifi_up(void)
{
	st.roam = 0;
	if (nl_set_cqm(&st.nl, st.ifindex, CQM_THOLD, CQM_HYST))
		printf("wifi: CQM not available\n");
	go(S_UP, 0);
	addr_up();
}

/* a roaming scan finished: move to a clearly better AP of the same network */
static void wifi_roam(void)
{
	static struct bss list[64];
	struct sta s;
	int n = nl_get_scan(&st.nl, st.ifindex, list, 64), j, best = -1, cur;

	st.roam = 0;
	cur = nl_get_station(&st.nl, st.ifindex, st.bss.bssid, &s) ? st.bss.signal_mbm / 100 : s.signal_avg;
	for (j = 0; j < n; j++)
		if (!strcmp(list[j].ssid, st.bss.ssid) && memcmp(list[j].bssid, st.bss.bssid, 6) &&
		    (st.c.ap[st.cur].enc == ENC_NONE ? !list[j].privacy : list[j].rsn_ok) &&
		    list[j].signal_mbm / 100 >= cur + ROAM_GAIN && (best < 0 || list[j].signal_mbm > list[best].signal_mbm))
			best = j;
	if (best < 0) {
		printf("wifi: roaming scan: no better AP (current %d dBm)\n", cur);
		return;
	}
	event("wifi: roaming to a better AP%s", "");
	printf("wifi: %d dBm -> %d dBm\n", cur, list[best].signal_mbm / 100);
	addr_down();
	nl_disconnect(&st.nl, st.ifindex);
	st.bss = list[best];
	st.roam_to = 1;			/* the next pick connects to this AP */
	go(S_WAIT, 1);
}

static void eapol_rx(void)
{
	uint8_t f[2048], out[512];
	struct wpa_keys k;
	struct sockaddr_ll from;
	socklen_t fl = sizeof(from);
	int n = (int)recvfrom(st.eapol, f, sizeof(f), MSG_DONTWAIT, (struct sockaddr *)&from, &fl), r, done, was_up;

	/* only while associated, and only from the AP we associated with (the CONNECT event set
	 * st.bss.bssid): a frame with another source address is somebody else's */
	if (n <= 0 || st.state < S_HANDSHAKE || st.state > S_UP || memcmp(from.sll_addr, st.bss.bssid, 6))
		return;
	was_up = st.state == S_UP;
	memset(&k, 0, sizeof(k));
	r = wpa_rx(&st.wpa, f, (size_t)n, out, sizeof(out), &k, &done, urandom);
	if (r > 0)
		eapol_send(out, r);			/* M2 / M4 / group 2/2 */
	if (!done)
		return;
	wifi_keys(&k, done);
	if (done & WPA_PTK) {
		nl_authorize(&st.nl, st.ifindex, st.bss.bssid);
		event("wifi: WPA2 handshake done%s", k.have_igtk && st.wpa.mfp ? " (IGTK)" : "");
		if (!was_up)			/* a PTK rekey of a running link keeps its address */
			wifi_up();
	} else {
		printf("wifi: group key renewed (idx %d)\n", k.gtk_idx);
	}
	fflush(stdout);
}

static void nl_rx(void)
{
	int status, ev = nl_event(&st.nl, &status);

	switch (ev) {
	case NL_EV_SCAN_DONE:
	case NL_EV_SCAN_ABORTED:
		if (st.state == S_SCAN)
			wifi_pick();
		else if (st.state == S_UP && st.roam)
			wifi_roam();
		break;
	case NL_EV_CQM_LOW:
		if (st.state == S_UP && !st.roam) {
			event("wifi: weak signal, looking for a better AP%s", "");
			const char *ss[1] = { st.bss.ssid };
			st.roam = !nl_trigger_scan(&st.nl, st.ifindex, ss, 1);
		}
		break;
	case NL_EV_CQM_HIGH:
		st.status_at = 0;
		break;
	case NL_EV_CONNECT:
		if (st.state != S_CONNECT)
			break;
		st.roam_to = 0;
		if (status) {
			printf("wifi: association failed (status %d)\n", status);
			go(S_WAIT, 5);
			break;
		}
		memcpy(st.bss.bssid, st.nl.bssid, 6);		/* the AP cfg80211 associated with */
		memcpy(st.wpa.aa, st.nl.bssid, 6);
		if (st.c.ap[st.cur].enc == ENC_NONE) {
			event("wifi: associated (open)%s", "");
			wifi_up();
		} else {
			go(S_HANDSHAKE, 10);		/* M1 comes from the AP */
		}
		break;
	case NL_EV_DISCONNECT:
		if (st.state >= S_CONNECT && st.state <= S_UP) {
			printf("wifi: disconnected (reason %d), reconnecting\n", status);
			addr_down();
			go(S_WAIT, 3);
		}
		break;
	}
	fflush(stdout);
}

/* ---- main loop ---- */
/* the log lives in RAM (initramfs): when stdout is a regular file, start over at 32 KB */
static void log_cap(void)
{
	struct stat s;

	if (!fstat(1, &s) && S_ISREG(s.st_mode) && s.st_size > 32768 && !ftruncate(1, 0))
		lseek(1, 0, SEEK_SET);
}

static void tick(void)
{
	time_t t = mono();

	log_cap();
	if (!st.status_at || t - st.status_at >= 5)
		status_write();

	if (!st.ifn)
		return;
	if (st.dhcp_on)
		dhcp_event(dhcp_tick(&st.dhcp));
	if (!st.wifi) {				/* cable: follow the carrier */
		int c = nc_carrier(st.ifn);

		if (st.state == S_LINK && c) {
			printf("eth: link up\n");
			go(S_UP, 0);
			addr_up();
		} else if (st.state == S_UP && !c) {
			printf("eth: link down\n");
			addr_down();
			go(S_LINK, 0);
		}
		return;
	}
	if (t < st.deadline)
		return;
	switch (st.state) {
	case S_SCAN:				/* no scan event: try the results anyway */
		wifi_pick();
		break;
	case S_CONNECT:
	case S_HANDSHAKE:
		printf("wifi: %s timed out\n", sname[st.state]);
		nl_disconnect(&st.nl, st.ifindex);
		go(S_WAIT, 3);
		break;
	case S_WAIT:
		wifi_scan();
		break;
	}
}

/* ---- interfaces (hot-plug) ---- */
static void nl_drain(void)		/* nl80211 events queued while Wi-Fi was not in use */
{
	struct pollfd p = { st.nl.ev, POLLIN, 0 };
	int s;

	while (poll(&p, 1, 0) > 0 && (p.revents & POLLIN))
		nl_event(&st.nl, &s);
}

/* eth0 with a carrier, else wlan0, else eth0 (waits for a cable); -i: only that one */
static const char *pick_if(void)
{
	int eth = nc_index("eth0") != 0;

	if (st.force)
		return nc_index(st.force) ? st.force : NULL;
	if (eth && nc_carrier("eth0"))
		return "eth0";
	if (nc_index("wlan0"))
		return "wlan0";
	return eth ? "eth0" : NULL;
}

static void detach(void)
{
	printf("interface: %s released\n", st.ifn);
	addr_down();
	if (st.wifi) {
		if (st.state >= S_CONNECT && st.state <= S_UP && nc_index(st.ifn) == st.ifindex)
			nl_disconnect(&st.nl, st.ifindex);
		if (st.eapol >= 0)
			close(st.eapol);
		st.eapol = -1;
	}
	st.ifn = NULL;
	st.ifindex = st.wifi = st.roam = st.roam_to = 0;
	go(S_NONE, 0);
}

static int attach(const char *ifn)
{
	st.ifn = ifn;
	st.ifindex = nc_index(ifn);
	st.wifi = !strncmp(ifn, "wlan", 4);
	nc_up(ifn);
	nc_hwaddr(ifn, st.mac);
	event("interface: %s", ifn);
	if (!st.wifi) {
		if (!st.force && !nc_carrier(ifn))
			printf("%s: no cable; waiting for a cable or wlan0\n", ifn);
		go(S_LINK, 0);
		return 0;
	}
	if (!st.nl_ok && nl_open(&st.nl)) {
		fprintf(stderr, "networkd: nl80211: %s\n", strerror(errno));
		if (st.nl.fd > 0)
			close(st.nl.fd);
		if (st.nl.ev > 0)
			close(st.nl.ev);
		st.ifn = NULL;
		return -1;
	}
	st.nl_ok = 1;
	if (!st.pmk_ok) {			/* PBKDF2, 4096 x HMAC-SHA1 each: only when Wi-Fi is used */
		int i;

		for (i = 0; i < st.c.n_ap; i++)
			if (st.c.ap[i].enc != ENC_NONE && supported(st.c.ap[i].enc))
				wpa_pmk(st.c.ap[i].key, (const uint8_t *)st.c.ap[i].ssid, strlen(st.c.ap[i].ssid),
					st.c.ap[i].pmk);
		st.pmk_ok = 1;
	}
	nl_drain();
	if ((st.eapol = eapol_open()) < 0) {
		fprintf(stderr, "networkd: EAPOL socket: %s\n", strerror(errno));
		st.ifn = NULL;
		return -1;
	}
	wifi_scan();
	return 0;
}

/* every loop pass (woken early by rtnetlink link events): follow what is plugged in */
static void hotplug(void)
{
	const char *want;

	if (nc_index("eth0"))
		nc_up("eth0");			/* a down interface reports no carrier */
	if (mono() < st.retry_at)
		return;
	want = pick_if();
	if (st.ifn && (!want || strcmp(want, st.ifn) || nc_index(st.ifn) != st.ifindex))
		detach();			/* gone, re-plugged, or a better one is there */
	if (!st.ifn && want && attach(want)) {
		st.retry_at = mono() + 10;
		go(S_NONE, 0);
	}
}

int main(int argc, char **argv)
{
	const char *file = "/dev/mtd7";
	long off = 0xF0000;
	int opt, print_only = 0, i, rtnl;

	while ((opt = getopt(argc, argv, "f:o:i:ps")) != -1) {
		switch (opt) {
		case 'f': file = optarg; break;
		case 'o': off = strtol(optarg, NULL, 0); break;
		case 'i': st.force = optarg; break;
		case 'p': print_only = 1; break;
		case 's': show = 1; break;
		default:
			fprintf(stderr, "usage: networkd [-f FILE] [-o OFFSET] [-i IF] [-p] [-s]\n");
			return 2;
		}
	}
	signal(SIGPIPE, SIG_IGN);
	if (load(file, off, &st.c))
		return 1;
	print_cfg(&st.c);
	if (print_only)
		return 0;
	st.eapol = -1;
	st.nl.fd = st.nl.ev = -1;
	if ((rtnl = nc_link_open()) < 0)
		fprintf(stderr, "networkd: rtnetlink: %s (polling only)\n", strerror(errno));
	st.state = S_NONE;
	hotplug();
	if (!st.ifn)
		printf("waiting for %s\n", st.force ? st.force : "eth0 or wlan0");
	for (;;) {
		struct pollfd p[4];
		int n = 0, to = 1000;

		if (rtnl >= 0) {
			p[n].fd = rtnl; p[n++].events = POLLIN;
		}
		if (st.wifi && st.eapol >= 0) {
			p[n].fd = st.nl.ev; p[n++].events = POLLIN;
			p[n].fd = st.eapol; p[n++].events = POLLIN;
		}
		if (st.dhcp_on) {
			p[n].fd = st.dhcp.fd; p[n++].events = POLLIN;
			if (dhcp_timeout_ms(&st.dhcp) < to)
				to = dhcp_timeout_ms(&st.dhcp);
		}
		if (poll(p, (nfds_t)n, to) < 0 && errno != EINTR)
			return 1;
		for (i = 0; i < n; i++) {
			if (!(p[i].revents & POLLIN))
				continue;
			if (p[i].fd == rtnl)
				nc_link_drain(rtnl);
			else if (st.wifi && p[i].fd == st.nl.ev)
				nl_rx();
			else if (st.wifi && p[i].fd == st.eapol)
				eapol_rx();
			else if (st.dhcp_on && p[i].fd == st.dhcp.fd)
				dhcp_event(dhcp_rx(&st.dhcp));
		}
		hotplug();
		if (st.ifn)
			tick();
		else if (!st.status_at || mono() - st.status_at >= 5)
			status_write();
	}
}
