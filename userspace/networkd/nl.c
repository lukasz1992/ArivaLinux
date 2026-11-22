/*
 * nl.c - minimal nl80211 client: generic netlink by hand (no libnl).  Station only:
 * scan, CONNECT (cfg80211 SME on mac80211 drivers such as rt2800usb), keys, authorize.
 * Uses only attributes present in Linux 4.4.
 */
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include "nl.h"
#include "wpa.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

struct msg { uint8_t b[2048]; int len; };

static struct nlmsghdr *hdr(struct msg *m) { return (struct nlmsghdr *)m->b; }

static void msg_init(struct msg *m, int type, int flags, int cmd)
{
	struct genlmsghdr *g;

	memset(m->b, 0, NLMSG_HDRLEN + GENL_HDRLEN);
	hdr(m)->nlmsg_type = (uint16_t)type;
	hdr(m)->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | flags);
	g = (struct genlmsghdr *)(m->b + NLMSG_HDRLEN);
	g->cmd = (uint8_t)cmd;
	g->version = 1;
	m->len = NLMSG_HDRLEN + GENL_HDRLEN;
}

static int put(struct msg *m, int type, const void *d, int len)
{
	struct nlattr *a = (struct nlattr *)(m->b + m->len);
	int tot = NLA_ALIGN(NLA_HDRLEN + len);

	if (m->len + tot > (int)sizeof(m->b))
		return -1;
	a->nla_type = (uint16_t)type;
	a->nla_len = (uint16_t)(NLA_HDRLEN + len);
	if (len)
		memcpy((uint8_t *)a + NLA_HDRLEN, d, (size_t)len);
	memset((uint8_t *)a + NLA_HDRLEN + len, 0, (size_t)(tot - NLA_HDRLEN - len));
	m->len += tot;
	return 0;
}

static void put32(struct msg *m, int t, uint32_t v) { put(m, t, &v, 4); }
static void put16(struct msg *m, int t, uint16_t v) { put(m, t, &v, 2); }
static void put8(struct msg *m, int t, uint8_t v) { put(m, t, &v, 1); }
static int nest(struct msg *m, int t) { int o = m->len; put(m, t | NLA_F_NESTED, NULL, 0); return o; }
static void nest_end(struct msg *m, int o) { ((struct nlattr *)(m->b + o))->nla_len = (uint16_t)(m->len - o); }

/* attributes of a payload into tb[] (up to max) */
static void parse(const uint8_t *p, int len, const struct nlattr **tb, int max)
{
	memset(tb, 0, sizeof(*tb) * (size_t)(max + 1));
	while (len >= NLA_HDRLEN) {
		const struct nlattr *a = (const struct nlattr *)p;
		int t = a->nla_type & NLA_TYPE_MASK;

		if (a->nla_len < NLA_HDRLEN || a->nla_len > len)
			break;
		if (t <= max)
			tb[t] = a;
		p += NLA_ALIGN(a->nla_len);
		len -= NLA_ALIGN(a->nla_len);
	}
}

#define DATA(a) ((const uint8_t *)(a) + NLA_HDRLEN)
#define DLEN(a) ((a)->nla_len - NLA_HDRLEN)
static uint32_t get32(const struct nlattr *a) { uint32_t v; memcpy(&v, DATA(a), 4); return v; }

/* send; for each reply message call cb (may be NULL); return 0 / -errno from the ACK */
static int talk(struct nl *n, struct msg *m, int (*cb)(const struct nlmsghdr *, void *), void *arg)
{
	static uint8_t rb[16384];
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	int r, dump = hdr(m)->nlmsg_flags & NLM_F_DUMP;

	hdr(m)->nlmsg_len = (uint32_t)m->len;
	hdr(m)->nlmsg_seq = ++n->seq;
	if (!dump)
		hdr(m)->nlmsg_flags |= NLM_F_ACK;
	if (sendto(n->fd, m->b, (size_t)m->len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -errno;
	for (;;) {
		struct nlmsghdr *h;

		r = (int)recv(n->fd, rb, sizeof(rb), 0);
		if (r < 0)
			return errno == EINTR ? -EINTR : -errno;
		for (h = (struct nlmsghdr *)rb; NLMSG_OK(h, (unsigned)r); h = NLMSG_NEXT(h, r)) {
			if (h->nlmsg_seq != n->seq)
				continue;
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;
			if (h->nlmsg_type == NLMSG_ERROR) {
				int e = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
				if (e || !dump)
					return e;
				continue;
			}
			if (cb)
				cb(h, arg);
		}
	}
}

struct fam { int id, g_scan, g_mlme; };

static int fam_cb(const struct nlmsghdr *h, void *arg)
{
	struct fam *f = arg;
	const struct nlattr *tb[CTRL_ATTR_MAX + 1], *g;
	const uint8_t *p;
	int len;

	parse((const uint8_t *)NLMSG_DATA(h) + GENL_HDRLEN, (int)(h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN), tb, CTRL_ATTR_MAX);
	if (tb[CTRL_ATTR_FAMILY_ID])
		f->id = *(const uint16_t *)DATA(tb[CTRL_ATTR_FAMILY_ID]);
	if (!(g = tb[CTRL_ATTR_MCAST_GROUPS]))
		return 0;
	for (p = DATA(g), len = DLEN(g); len >= NLA_HDRLEN;) {
		const struct nlattr *e = (const struct nlattr *)p, *gt[CTRL_ATTR_MCAST_GRP_MAX + 1];

		parse(DATA(e), DLEN(e), gt, CTRL_ATTR_MCAST_GRP_MAX);
		if (gt[CTRL_ATTR_MCAST_GRP_NAME] && gt[CTRL_ATTR_MCAST_GRP_ID]) {
			const char *nm = (const char *)DATA(gt[CTRL_ATTR_MCAST_GRP_NAME]);
			if (!strcmp(nm, "scan")) f->g_scan = (int)get32(gt[CTRL_ATTR_MCAST_GRP_ID]);
			if (!strcmp(nm, "mlme")) f->g_mlme = (int)get32(gt[CTRL_ATTR_MCAST_GRP_ID]);
		}
		p += NLA_ALIGN(e->nla_len);
		len -= NLA_ALIGN(e->nla_len);
	}
	return 0;
}

int nl_open(struct nl *n)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct fam f = { 0, -1, -1 };
	struct msg m;

	memset(n, 0, sizeof(*n));
	n->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	n->ev = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (n->fd < 0 || n->ev < 0 || bind(n->fd, (struct sockaddr *)&sa, sizeof(sa)) || bind(n->ev, (struct sockaddr *)&sa, sizeof(sa)))
		return -1;
	msg_init(&m, GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY);
	put(&m, CTRL_ATTR_FAMILY_NAME, "nl80211", 8);
	if (talk(n, &m, fam_cb, &f) || !f.id || f.g_scan < 0 || f.g_mlme < 0)
		return -1;
	n->family = f.id;
	setsockopt(n->ev, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &f.g_scan, sizeof(f.g_scan));
	setsockopt(n->ev, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &f.g_mlme, sizeof(f.g_mlme));
	return 0;
}

int nl_trigger_scan(struct nl *n, int ifindex, const char *const *ssids, int nssid)
{
	struct msg m;
	int o, i;

	msg_init(&m, n->family, 0, NL80211_CMD_TRIGGER_SCAN);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	o = nest(&m, NL80211_ATTR_SCAN_SSIDS);
	for (i = 0; i < nssid; i++)			/* probe for hidden networks of the list */
		put(&m, i + 1, ssids[i], (int)strlen(ssids[i]));
	put(&m, i + 1, "", 0);				/* and a wildcard probe */
	nest_end(&m, o);
	return talk(n, &m, NULL, NULL);
}

struct scan_arg { struct bss *out; int max, n; };

static void parse_ies(struct bss *b, const uint8_t *p, int len)
{
	while (len >= 2 && p[1] + 2 <= len) {
		if (p[0] == 0 && p[1] <= 32) {
			memcpy(b->ssid, p + 2, p[1]);
			b->ssid[p[1]] = 0;
		} else if (p[0] == 48) {
			b->rsn_ok = !wpa_rsn_parse(p, p[1] + 2, &b->akm, &b->mfpc, &b->mfpr);
		}
		len -= p[1] + 2;
		p += p[1] + 2;
	}
}

static int scan_cb(const struct nlmsghdr *h, void *arg)
{
	struct scan_arg *s = arg;
	const struct nlattr *tb[NL80211_ATTR_MAX + 1], *bt[NL80211_BSS_MAX + 1];
	struct bss *b;

	if (s->n >= s->max)
		return 0;
	parse((const uint8_t *)NLMSG_DATA(h) + GENL_HDRLEN, (int)(h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN), tb, NL80211_ATTR_MAX);
	if (!tb[NL80211_ATTR_BSS])
		return 0;
	parse(DATA(tb[NL80211_ATTR_BSS]), DLEN(tb[NL80211_ATTR_BSS]), bt, NL80211_BSS_MAX);
	if (!bt[NL80211_BSS_BSSID] || !bt[NL80211_BSS_FREQUENCY])
		return 0;
	b = &s->out[s->n++];
	memset(b, 0, sizeof(*b));
	memcpy(b->bssid, DATA(bt[NL80211_BSS_BSSID]), 6);
	b->freq = get32(bt[NL80211_BSS_FREQUENCY]);
	b->signal_mbm = bt[NL80211_BSS_SIGNAL_MBM] ? (int)get32(bt[NL80211_BSS_SIGNAL_MBM]) : -10000;
	if (bt[NL80211_BSS_CAPABILITY])
		b->privacy = !!(*(const uint16_t *)DATA(bt[NL80211_BSS_CAPABILITY]) & 0x10);
	if (bt[NL80211_BSS_INFORMATION_ELEMENTS])
		parse_ies(b, DATA(bt[NL80211_BSS_INFORMATION_ELEMENTS]), DLEN(bt[NL80211_BSS_INFORMATION_ELEMENTS]));
	return 0;
}

int nl_get_scan(struct nl *n, int ifindex, struct bss *out, int max)
{
	struct msg m;
	struct scan_arg s = { out, max, 0 };

	msg_init(&m, n->family, NLM_F_DUMP, NL80211_CMD_GET_SCAN);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	return talk(n, &m, scan_cb, &s) ? -1 : s.n;
}

int nl_connect(struct nl *n, int ifindex, const char *ssid, const uint8_t *bssid, uint32_t freq,
	       const uint8_t *ie, int ie_len, int akm, int mfp)
{
	struct msg m;

	msg_init(&m, n->family, 0, NL80211_CMD_CONNECT);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	put(&m, NL80211_ATTR_SSID, ssid, (int)strlen(ssid));
	if (bssid) {
		put(&m, NL80211_ATTR_MAC, bssid, 6);
		put32(&m, NL80211_ATTR_WIPHY_FREQ, freq);
	}
	put32(&m, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
	if (ie_len) {
		uint32_t pw = WPA_CIPHER_CCMP, a = 0x000FAC00u | (uint32_t)akm;
		put(&m, NL80211_ATTR_PRIVACY, NULL, 0);
		put32(&m, NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2);
		put(&m, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, &pw, 4);
		put32(&m, NL80211_ATTR_CIPHER_SUITE_GROUP, WPA_CIPHER_CCMP);
		put(&m, NL80211_ATTR_AKM_SUITES, &a, 4);
		put(&m, NL80211_ATTR_IE, ie, ie_len);
		put(&m, NL80211_ATTR_CONTROL_PORT, NULL, 0);	/* data blocked until authorized */
		if (mfp)
			put32(&m, NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED);
	}
	return talk(n, &m, NULL, NULL);
}

int nl_disconnect(struct nl *n, int ifindex)
{
	struct msg m;

	msg_init(&m, n->family, 0, NL80211_CMD_DISCONNECT);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	put16(&m, NL80211_ATTR_REASON_CODE, 3);		/* deauth leaving */
	return talk(n, &m, NULL, NULL);
}

int nl_new_key(struct nl *n, int ifindex, int idx, uint32_t cipher, const uint8_t *key, int klen,
	       const uint8_t *seq, int seqlen, const uint8_t *mac)
{
	struct msg m;

	msg_init(&m, n->family, 0, NL80211_CMD_NEW_KEY);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	put(&m, NL80211_ATTR_KEY_DATA, key, klen);
	put8(&m, NL80211_ATTR_KEY_IDX, (uint8_t)idx);
	put32(&m, NL80211_ATTR_KEY_CIPHER, cipher);
	if (seqlen)
		put(&m, NL80211_ATTR_KEY_SEQ, seq, seqlen);
	if (mac) {
		put(&m, NL80211_ATTR_MAC, mac, 6);
		put32(&m, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_PAIRWISE);
	} else {
		put32(&m, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
	}
	return talk(n, &m, NULL, NULL);
}

int nl_authorize(struct nl *n, int ifindex, const uint8_t *bssid)
{
	struct msg m;
	struct nl80211_sta_flag_update u = { 1u << NL80211_STA_FLAG_AUTHORIZED, 1u << NL80211_STA_FLAG_AUTHORIZED };

	msg_init(&m, n->family, 0, NL80211_CMD_SET_STATION);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	put(&m, NL80211_ATTR_MAC, bssid, 6);
	put(&m, NL80211_ATTR_STA_FLAGS2, &u, sizeof(u));
	return talk(n, &m, NULL, NULL);
}

int nl_set_cqm(struct nl *n, int ifindex, int thold_dbm, int hyst_db)
{
	struct msg m;
	int o;

	msg_init(&m, n->family, 0, NL80211_CMD_SET_CQM);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	o = nest(&m, NL80211_ATTR_CQM);
	put32(&m, NL80211_ATTR_CQM_RSSI_THOLD, (uint32_t)thold_dbm);
	put32(&m, NL80211_ATTR_CQM_RSSI_HYST, (uint32_t)hyst_db);
	nest_end(&m, o);
	return talk(n, &m, NULL, NULL);
}

static int sta_cb(const struct nlmsghdr *h, void *arg)
{
	struct sta *s = arg;
	const struct nlattr *tb[NL80211_ATTR_MAX + 1], *si[NL80211_STA_INFO_MAX + 1], *ri[NL80211_RATE_INFO_MAX + 1];

	parse((const uint8_t *)NLMSG_DATA(h) + GENL_HDRLEN, (int)(h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN), tb, NL80211_ATTR_MAX);
	if (!tb[NL80211_ATTR_STA_INFO])
		return 0;
	parse(DATA(tb[NL80211_ATTR_STA_INFO]), DLEN(tb[NL80211_ATTR_STA_INFO]), si, NL80211_STA_INFO_MAX);
	if (si[NL80211_STA_INFO_SIGNAL]) s->signal = (int8_t)*DATA(si[NL80211_STA_INFO_SIGNAL]);
	if (si[NL80211_STA_INFO_SIGNAL_AVG]) s->signal_avg = (int8_t)*DATA(si[NL80211_STA_INFO_SIGNAL_AVG]);
	if (si[NL80211_STA_INFO_RX_BYTES]) s->rx_bytes = get32(si[NL80211_STA_INFO_RX_BYTES]);
	if (si[NL80211_STA_INFO_TX_BYTES]) s->tx_bytes = get32(si[NL80211_STA_INFO_TX_BYTES]);
	if (si[NL80211_STA_INFO_CONNECTED_TIME]) s->connected_time = get32(si[NL80211_STA_INFO_CONNECTED_TIME]);
	if (si[NL80211_STA_INFO_TX_FAILED]) s->tx_failed = get32(si[NL80211_STA_INFO_TX_FAILED]);
	if (si[NL80211_STA_INFO_TX_RETRIES]) s->tx_retries = get32(si[NL80211_STA_INFO_TX_RETRIES]);
	if (si[NL80211_STA_INFO_TX_BITRATE]) {
		parse(DATA(si[NL80211_STA_INFO_TX_BITRATE]), DLEN(si[NL80211_STA_INFO_TX_BITRATE]), ri, NL80211_RATE_INFO_MAX);
		if (ri[NL80211_RATE_INFO_BITRATE32]) s->tx_rate = (int)get32(ri[NL80211_RATE_INFO_BITRATE32]);
		else if (ri[NL80211_RATE_INFO_BITRATE]) s->tx_rate = *(const uint16_t *)DATA(ri[NL80211_RATE_INFO_BITRATE]);
	}
	return 0;
}

int nl_get_station(struct nl *n, int ifindex, const uint8_t *mac, struct sta *s)
{
	struct msg m;

	memset(s, 0, sizeof(*s));
	msg_init(&m, n->family, 0, NL80211_CMD_GET_STATION);
	put32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	put(&m, NL80211_ATTR_MAC, mac, 6);
	return talk(n, &m, sta_cb, s);
}

int nl_event(struct nl *n, int *status)
{
	static uint8_t rb[8192];
	struct nlmsghdr *h;
	int r = (int)recv(n->ev, rb, sizeof(rb), MSG_DONTWAIT), ev = NL_EV_NONE;

	*status = 0;
	for (h = (struct nlmsghdr *)rb; r > 0 && NLMSG_OK(h, (unsigned)r); h = NLMSG_NEXT(h, r)) {
		const struct genlmsghdr *g = NLMSG_DATA(h);
		const struct nlattr *tb[NL80211_ATTR_MAX + 1];

		if (h->nlmsg_type != n->family)
			continue;
		parse((const uint8_t *)g + GENL_HDRLEN, (int)(h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN), tb, NL80211_ATTR_MAX);
		switch (g->cmd) {
		case NL80211_CMD_NEW_SCAN_RESULTS: ev = NL_EV_SCAN_DONE; break;
		case NL80211_CMD_SCAN_ABORTED: ev = NL_EV_SCAN_ABORTED; break;
		case NL80211_CMD_CONNECT:
			ev = NL_EV_CONNECT;
			if (tb[NL80211_ATTR_MAC])
				memcpy(n->bssid, DATA(tb[NL80211_ATTR_MAC]), 6);
			*status = tb[NL80211_ATTR_STATUS_CODE] ? *(const uint16_t *)DATA(tb[NL80211_ATTR_STATUS_CODE]) : 1;
			break;
		case NL80211_CMD_NOTIFY_CQM:
			if (tb[NL80211_ATTR_CQM]) {
				const struct nlattr *cq[NL80211_ATTR_CQM_MAX + 1];

				parse(DATA(tb[NL80211_ATTR_CQM]), DLEN(tb[NL80211_ATTR_CQM]), cq, NL80211_ATTR_CQM_MAX);
				if (cq[NL80211_ATTR_CQM_BEACON_LOSS_EVENT])
					ev = NL_EV_BEACON_LOSS;
				else if (cq[NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT])
					ev = get32(cq[NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT]) == NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW ?
					     NL_EV_CQM_LOW : NL_EV_CQM_HIGH;
			}
			break;
		case NL80211_CMD_DISCONNECT:
			ev = NL_EV_DISCONNECT;
			*status = tb[NL80211_ATTR_REASON_CODE] ? *(const uint16_t *)DATA(tb[NL80211_ATTR_REASON_CODE]) : 0;
			break;
		}
	}
	return ev;
}
