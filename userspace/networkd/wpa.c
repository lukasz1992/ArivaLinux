/*
 * wpa.c - WPA2-PSK (CCMP only, optional MFP / PSK-SHA256) supplicant core on BearSSL primitives.
 * IEEE 802.11-2016 12.7: PBKDF2 PMK, PRF/KDF PTK, EAPOL-Key 4-way and group key handshakes,
 * key data AES key wrap (RFC 3394), GTK / IGTK KDEs.  No sockets here: wpa_rx() takes a frame
 * and returns the reply.  WEP, TKIP and WPA1 are deliberately not supported.
 */
#include <string.h>
#include <bearssl.h>
#include "wpa.h"

/* ---- primitives ---- */
static void hmac(const br_hash_class *h, const uint8_t *key, size_t klen, const void *const *parts,
		 const size_t *lens, int n, uint8_t *out)
{
	br_hmac_key_context kc;
	br_hmac_context hc;
	int i;

	br_hmac_key_init(&kc, h, key, klen);
	br_hmac_init(&hc, &kc, 0);
	for (i = 0; i < n; i++)
		br_hmac_update(&hc, parts[i], lens[i]);
	br_hmac_out(&hc, out);
}

void wpa_pmk(const char *pass, const uint8_t *ssid, size_t ssid_len, uint8_t pmk[32])
{
	/* PBKDF2-HMAC-SHA1(pass, ssid, 4096, 32) */
	uint8_t u[20], t[20], cnt[4];
	int b, i, j;

	for (b = 1; b <= 2; b++) {
		const void *p1[] = { ssid, cnt };
		size_t l1[] = { ssid_len, 4 };

		cnt[0] = 0; cnt[1] = 0; cnt[2] = 0; cnt[3] = (uint8_t)b;
		hmac(&br_sha1_vtable, (const uint8_t *)pass, strlen(pass), p1, l1, 2, u);
		memcpy(t, u, 20);
		for (i = 1; i < 4096; i++) {
			const void *p2[] = { u };
			size_t l2[] = { 20 };

			hmac(&br_sha1_vtable, (const uint8_t *)pass, strlen(pass), p2, l2, 1, u);
			for (j = 0; j < 20; j++)
				t[j] ^= u[j];
		}
		memcpy(pmk + 20 * (b - 1), t, b == 1 ? 20 : 12);
	}
}

void wpa_prf_sha1(const uint8_t *key, size_t klen, const char *label, const uint8_t *data, size_t dlen,
		  uint8_t *out, size_t olen)
{
	uint8_t z = 0, i = 0, h[20];
	size_t pos = 0, n;

	while (pos < olen) {
		const void *p[] = { label, &z, data, &i };
		size_t l[] = { strlen(label), 1, dlen, 1 };

		hmac(&br_sha1_vtable, key, klen, p, l, 4, h);
		n = olen - pos < 20 ? olen - pos : 20;
		memcpy(out + pos, h, n);
		pos += n;
		i++;
	}
}

void wpa_kdf_sha256(const uint8_t *key, size_t klen, const char *label, const uint8_t *data, size_t dlen,
		    uint8_t *out, size_t olen)
{
	uint8_t h[32], ctr[2], bits[2] = { (uint8_t)(olen * 8), (uint8_t)(olen * 8 >> 8) };
	size_t pos = 0, n;
	int i = 1;

	while (pos < olen) {
		const void *p[] = { ctr, label, data, bits };
		size_t l[] = { 2, strlen(label), dlen, 2 };

		ctr[0] = (uint8_t)i; ctr[1] = (uint8_t)(i >> 8);
		hmac(&br_sha256_vtable, key, klen, p, l, 4, h);
		n = olen - pos < 32 ? olen - pos : 32;
		memcpy(out + pos, h, n);
		pos += n;
		i++;
	}
}

static void aes_enc(const uint8_t *key, uint8_t blk[16])
{
	br_aes_ct_cbcenc_keys c;
	uint8_t iv[16] = { 0 };

	br_aes_ct_cbcenc_init(&c, key, 16);
	br_aes_ct_cbcenc_run(&c, iv, blk, 16);
}

static void aes_dec(const uint8_t *key, uint8_t blk[16])
{
	br_aes_ct_cbcdec_keys c;
	uint8_t iv[16] = { 0 };

	br_aes_ct_cbcdec_init(&c, key, 16);
	br_aes_ct_cbcdec_run(&c, iv, blk, 16);
}

void wpa_aes_wrap(const uint8_t *kek, const uint8_t *in, size_t len, uint8_t *out)
{
	size_t n = len / 8, i, j;
	uint8_t a[8], b[16];

	memset(a, 0xA6, 8);
	memcpy(out + 8, in, len);
	for (j = 0; j < 6; j++)
		for (i = 1; i <= n; i++) {
			uint64_t t = n * j + i;
			int k;

			memcpy(b, a, 8);
			memcpy(b + 8, out + 8 * i, 8);
			aes_enc(kek, b);
			memcpy(a, b, 8);
			for (k = 7; k >= 0; k--, t >>= 8)
				a[k] ^= (uint8_t)t;
			memcpy(out + 8 * i, b + 8, 8);
		}
	memcpy(out, a, 8);
}

int wpa_aes_unwrap(const uint8_t *kek, const uint8_t *in, size_t len, uint8_t *out)
{
	size_t n = len / 8 - 1, i;
	int j, k;
	uint8_t a[8], b[16];

	if (len % 8 || len < 24)
		return -1;
	memcpy(a, in, 8);
	memcpy(out, in + 8, len - 8);
	for (j = 5; j >= 0; j--)
		for (i = n; i >= 1; i--) {
			uint64_t t = n * j + i;

			for (k = 7; k >= 0; k--, t >>= 8)
				a[k] ^= (uint8_t)t;
			memcpy(b, a, 8);
			memcpy(b + 8, out + 8 * (i - 1), 8);
			aes_dec(kek, b);
			memcpy(a, b, 8);
			memcpy(out + 8 * (i - 1), b + 8, 8);
		}
	for (k = 0; k < 8; k++)
		if (a[k] != 0xA6)
			return -1;
	return 0;
}

static void aes_cmac(const uint8_t *key, const uint8_t *m, size_t len, uint8_t mac[16])
{
	uint8_t l[16] = { 0 }, k1[16], k2[16], x[16] = { 0 }, last[16];
	size_t nb = (len + 15) / 16, i;
	int j, c;

	aes_enc(key, l);
	for (c = 0, j = 15; j >= 0; j--) { int nc = l[j] >> 7; k1[j] = (uint8_t)(l[j] << 1 | c); c = nc; }
	if (l[0] & 0x80) k1[15] ^= 0x87;
	for (c = 0, j = 15; j >= 0; j--) { int nc = k1[j] >> 7; k2[j] = (uint8_t)(k1[j] << 1 | c); c = nc; }
	if (k1[0] & 0x80) k2[15] ^= 0x87;
	if (!nb)
		nb = 1;
	for (i = 0; i < nb - 1; i++) {
		for (j = 0; j < 16; j++)
			x[j] ^= m[16 * i + j];
		aes_enc(key, x);
	}
	memset(last, 0, 16);
	if (len && len % 16 == 0) {
		memcpy(last, m + 16 * (nb - 1), 16);
		for (j = 0; j < 16; j++) last[j] ^= k1[j];
	} else {
		size_t r = len - 16 * (nb - 1);
		memcpy(last, m + 16 * (nb - 1), r);
		last[r] = 0x80;
		for (j = 0; j < 16; j++) last[j] ^= k2[j];
	}
	for (j = 0; j < 16; j++)
		x[j] ^= last[j];
	aes_enc(key, x);
	memcpy(mac, x, 16);
}

void wpa_mic(int ver, const uint8_t *kck, const uint8_t *data, size_t len, uint8_t mic[16])
{
	if (ver == 3) {
		aes_cmac(kck, data, len, mic);
	} else {
		uint8_t h[20];
		const void *p[] = { data };
		size_t l[] = { len };

		hmac(&br_sha1_vtable, kck, 16, p, l, 1, h);
		memcpy(mic, h, 16);
	}
}

/* ---- RSN IE ---- */
static const uint8_t oui[3] = { 0x00, 0x0F, 0xAC };

int wpa_rsn_ie(uint8_t *ie, int akm, int mfpc, int mfpr)
{
	int n = 0;
	uint16_t caps = (uint16_t)((mfpc ? 0x80 : 0) | (mfpr ? 0x40 : 0));

	ie[n++] = 48; ie[n++] = 0;
	ie[n++] = 1; ie[n++] = 0;				/* version 1 */
	memcpy(ie + n, oui, 3); n += 3; ie[n++] = 4;		/* group CCMP */
	ie[n++] = 1; ie[n++] = 0; memcpy(ie + n, oui, 3); n += 3; ie[n++] = 4;	/* pairwise CCMP */
	ie[n++] = 1; ie[n++] = 0; memcpy(ie + n, oui, 3); n += 3; ie[n++] = (uint8_t)akm;
	ie[n++] = (uint8_t)caps; ie[n++] = (uint8_t)(caps >> 8);
	ie[1] = (uint8_t)(n - 2);
	return n;
}

int wpa_rsn_parse(const uint8_t *ie, int len, int *akm, int *mfpc, int *mfpr)
{
	int p = 2, n, i, ccmp = 0, a2 = 0, a6 = 0;
	uint16_t caps = 0;

	if (len < 8 || ie[0] != 48 || ie[2] != 1)
		return -1;
	if (memcmp(ie + 4, oui, 3) || ie[7] != 4)
		return -1;				/* group cipher must be CCMP (no TKIP) */
	p = 8;
	if (p + 2 > len) return -1;
	n = ie[p] | ie[p + 1] << 8; p += 2;
	for (i = 0; i < n && p + 4 <= len; i++, p += 4)
		if (!memcmp(ie + p, oui, 3) && ie[p + 3] == 4)
			ccmp = 1;
	if (p + 2 > len) return -1;
	n = ie[p] | ie[p + 1] << 8; p += 2;
	for (i = 0; i < n && p + 4 <= len; i++, p += 4)
		if (!memcmp(ie + p, oui, 3)) {
			if (ie[p + 3] == 2) a2 = 1;
			if (ie[p + 3] == 6) a6 = 1;
		}
	if (p + 2 <= len)
		caps = (uint16_t)(ie[p] | ie[p + 1] << 8);
	if (!ccmp || (!a2 && !a6))
		return -1;
	*mfpc = !!(caps & 0x80);
	*mfpr = !!(caps & 0x40);
	*akm = a2 && !(*mfpr && a6) ? WPA_AKM_PSK : WPA_AKM_PSK_SHA256;
	return 0;
}

/* ---- EAPOL-Key ---- */
#define KI_VER		0x0007
#define KI_PAIRWISE	0x0008
#define KI_INSTALL	0x0040
#define KI_ACK		0x0080
#define KI_MIC		0x0100
#define KI_SECURE	0x0200
#define KI_ENCDATA	0x1000
#define HDR		4		/* 802.1X header */
#define KD_LEN		95		/* key descriptor up to key data length, MIC 16 */
#define OFF_INFO	(HDR + 1)
#define OFF_REPLAY	(HDR + 5)
#define OFF_NONCE	(HDR + 13)
#define OFF_RSC		(HDR + 61)
#define OFF_MIC		(HDR + 77)
#define OFF_DLEN	(HDR + 93)
#define OFF_DATA	(HDR + 95)

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static void derive_ptk(const struct wpa *w, const uint8_t *anonce, const uint8_t *snonce,
		       uint8_t kck[16], uint8_t kek[16], uint8_t tk[16])
{
	uint8_t d[76], ptk[48];
	int a = memcmp(w->aa, w->spa, 6) < 0, n = memcmp(anonce, snonce, 32) < 0;

	memcpy(d, a ? w->aa : w->spa, 6);
	memcpy(d + 6, a ? w->spa : w->aa, 6);
	memcpy(d + 12, n ? anonce : snonce, 32);
	memcpy(d + 44, n ? snonce : anonce, 32);
	if (w->akm == WPA_AKM_PSK_SHA256)
		wpa_kdf_sha256(w->pmk, 32, "Pairwise key expansion", d, 76, ptk, 48);
	else
		wpa_prf_sha1(w->pmk, 32, "Pairwise key expansion", d, 76, ptk, 48);
	memcpy(kck, ptk, 16);
	memcpy(kek, ptk + 16, 16);
	memcpy(tk, ptk + 32, 16);
}

/* reply: copy of the header layout, our key info, replay, nonce, data; MIC filled in */
static int reply(const uint8_t *kck, const uint8_t *req, uint16_t info, const uint8_t *nonce,
		 const uint8_t *data, int dlen, uint8_t *out, size_t out_size)
{
	int len = HDR + KD_LEN + dlen;

	if ((size_t)len > out_size)
		return -1;
	memset(out, 0, (size_t)len);
	out[0] = req[0];				/* 802.1X version as the AP's */
	out[1] = 3;					/* EAPOL-Key */
	out[2] = (uint8_t)((len - HDR) >> 8); out[3] = (uint8_t)(len - HDR);
	out[HDR] = 2;					/* RSN key descriptor */
	out[OFF_INFO] = (uint8_t)(info >> 8); out[OFF_INFO + 1] = (uint8_t)info;
	memcpy(out + OFF_REPLAY, req + OFF_REPLAY, 8);
	if (nonce)
		memcpy(out + OFF_NONCE, nonce, 32);
	out[OFF_DLEN] = (uint8_t)(dlen >> 8); out[OFF_DLEN + 1] = (uint8_t)dlen;
	if (dlen)
		memcpy(out + OFF_DATA, data, (size_t)dlen);
	wpa_mic(info & KI_VER, kck, out, (size_t)len, out + OFF_MIC);
	return len;
}

static int check_mic(const uint8_t *kck, const uint8_t *f, size_t len, int ver)
{
	uint8_t tmp[2048], mic[16];

	if (len > sizeof(tmp))
		return -1;
	memcpy(tmp, f, len);
	memset(tmp + OFF_MIC, 0, 16);
	wpa_mic(ver, kck, tmp, len, mic);
	return memcmp(mic, f + OFF_MIC, 16) ? -1 : 0;
}

/* KDEs in decrypted key data: GTK (00-0F-AC:1) and IGTK (00-0F-AC:9) */
static int parse_kdes(const uint8_t *d, int len, struct wpa_keys *k)
{
	int p = 0;

	while (p + 2 <= len) {
		int t = d[p], l = d[p + 1];

		if (t == 0xDD && l == 0)
			break;					/* padding */
		if (p + 2 + l > len)
			return -1;
		if (t == 0xDD && l >= 4 && !memcmp(d + p + 2, oui, 3)) {
			const uint8_t *v = d + p + 6;
			int vl = l - 4;

			if (d[p + 5] == 1 && vl >= 2 + 16 && vl - 2 <= 32) {
				k->gtk_idx = v[0] & 3;
				k->gtk_len = vl - 2;
				memcpy(k->gtk, v + 2, (size_t)k->gtk_len);
				k->have_gtk = 1;
			} else if (d[p + 5] == 9 && vl >= 2 + 6 + 16) {
				k->igtk_idx = v[0] | v[1] << 8;
				memcpy(k->ipn, v + 2, 6);
				memcpy(k->igtk, v + 8, 16);
				k->have_igtk = 1;
			}
		}
		p += 2 + l;
	}
	return 0;
}

static int decrypt_data(const uint8_t *kek, const uint8_t *f, size_t len, struct wpa_keys *k)
{
	int dlen = be16(f + OFF_DLEN);
	uint8_t plain[1024];

	if (OFF_DATA + (size_t)dlen > len || dlen > (int)sizeof(plain) + 8 || wpa_aes_unwrap(kek, f + OFF_DATA, (size_t)dlen, plain))
		return -1;
	return parse_kdes(plain, dlen - 8, k);
}

int wpa_rx(struct wpa *w, const uint8_t *f, size_t len, uint8_t *out, size_t out_size,
	   struct wpa_keys *k, int *done, int (*rnd)(uint8_t *, size_t))
{
	uint16_t info;
	int ver;

	*done = 0;
	if (len < OFF_DATA || f[1] != 3 || f[HDR] != 2 || OFF_DATA + (size_t)be16(f + OFF_DLEN) > len)
		return -1;
	info = be16(f + OFF_INFO);
	ver = info & KI_VER;
	if (!(info & KI_ACK) || ver != (w->akm == WPA_AKM_PSK_SHA256 ? 3 : 2))
		return -1;
	if (w->replay_ok && memcmp(f + OFF_REPLAY, w->replay, 8) <= 0)
		return -1;					/* replayed */

	if ((info & KI_PAIRWISE) && !(info & KI_MIC)) {		/* message 1/4 */
		memcpy(w->t_anonce, f + OFF_NONCE, 32);
		if (rnd(w->t_snonce, 32))
			return -1;
		derive_ptk(w, w->t_anonce, w->t_snonce, w->t_kck, w->t_kek, w->t_tk);
		w->t_ok = 1;			/* committed by a verified M3; the replay counter stays */
		return reply(w->t_kck, f, (uint16_t)(ver | KI_PAIRWISE | KI_MIC), w->t_snonce, w->ie, w->ie_len, out, out_size);
	}
	if (!(info & KI_MIC))
		return -1;
	if (info & KI_PAIRWISE) {					/* message 3/4 */
		/* the pending PTK, or (M4 lost, the AP resends M3) the committed one */
		int pend = w->t_ok;
		const uint8_t *an = pend ? w->t_anonce : w->anonce;
		const uint8_t *kck = pend ? w->t_kck : w->kck, *kek = pend ? w->t_kek : w->kek;

		if (!(pend || w->ptk_ok) || check_mic(kck, f, len, ver))
			return -1;
		if (memcmp(f + OFF_NONCE, an, 32) || !(info & KI_ENCDATA) || decrypt_data(kek, f, len, k))
			return -1;
		if (pend) {
			memcpy(w->anonce, w->t_anonce, 32); memcpy(w->snonce, w->t_snonce, 32);
			memcpy(w->kck, w->t_kck, 16); memcpy(w->kek, w->t_kek, 16); memcpy(w->tk, w->t_tk, 16);
			w->ptk_ok = 1;
			w->t_ok = 0;
		}
		memcpy(w->replay, f + OFF_REPLAY, 8); w->replay_ok = 1;
		memcpy(k->tk, w->tk, 16);
		k->have_ptk = 1;
		memcpy(k->gtk_rsc, f + OFF_RSC, 8);
		*done = WPA_PTK | (k->have_gtk ? WPA_GTK : 0);
		return reply(w->kck, f, (uint16_t)(ver | KI_PAIRWISE | KI_MIC | KI_SECURE), NULL, NULL, 0, out, out_size);
	}
	if (!w->ptk_ok || check_mic(w->kck, f, len, ver))
		return -1;
	/* group key handshake 1/2 (GTK rekey) */
	if (!(info & KI_ENCDATA))
		return -1;
	k->have_gtk = 0; k->have_igtk = 0;
	if (decrypt_data(w->kek, f, len, k) || !k->have_gtk)
		return -1;
	memcpy(w->replay, f + OFF_REPLAY, 8);
	memcpy(k->gtk_rsc, f + OFF_RSC, 8);
	*done = WPA_GTK;
	return reply(w->kck, f, (uint16_t)(ver | KI_MIC | KI_SECURE), NULL, NULL, 0, out, out_size);
}
