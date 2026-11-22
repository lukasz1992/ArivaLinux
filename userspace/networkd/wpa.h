/* wpa.h - WPA2-PSK (CCMP) supplicant core: crypto and the EAPOL-Key state machine, no I/O. */
#ifndef WPA_H
#define WPA_H
#include <stddef.h>
#include <stdint.h>

#define WPA_AKM_PSK		2	/* 00-0F-AC:2, key descriptor version 2 (HMAC-SHA1 MIC) */
#define WPA_AKM_PSK_SHA256	6	/* 00-0F-AC:6, version 3 (AES-CMAC MIC, KDF-SHA256) */
#define WPA_CIPHER_CCMP		0x000FAC04
#define WPA_CIPHER_BIP		0x000FAC06

struct wpa_keys {			/* what the I/O layer installs */
	uint8_t tk[16];
	int have_ptk;
	uint8_t gtk[32]; int gtk_len, gtk_idx; uint8_t gtk_rsc[8];
	int have_gtk;
	uint8_t igtk[16]; int igtk_idx; uint8_t ipn[6];
	int have_igtk;
};

struct wpa {
	/* set by the caller before the handshake */
	uint8_t pmk[32];
	uint8_t aa[6], spa[6];		/* authenticator (AP) and supplicant MAC */
	int akm, mfp;			/* WPA_AKM_*, management frame protection in use */
	uint8_t ie[32]; int ie_len;	/* our RSN IE as sent in (Re)Association */
	/* state */
	uint8_t anonce[32], snonce[32];
	uint8_t kck[16], kek[16], tk[16];	/* the committed PTK: verified by an M3 */
	int ptk_ok;
	/* the PTK of an M1 still waiting for its M3 (TPTK): an unauthenticated M1 must not touch
	 * the live keys or the replay counter, or one forged frame would break every later rekey */
	uint8_t t_anonce[32], t_snonce[32], t_kck[16], t_kek[16], t_tk[16];
	int t_ok;
	uint8_t replay[8]; int replay_ok;
};

void wpa_pmk(const char *pass, const uint8_t *ssid, size_t ssid_len, uint8_t pmk[32]);
int wpa_rsn_ie(uint8_t *ie, int akm, int mfpc, int mfpr);
/* parse an RSN IE (from a beacon): 0 if it allows CCMP/CCMP + PSK or PSK-SHA256 */
int wpa_rsn_parse(const uint8_t *ie, int len, int *akm, int *mfpc, int *mfpr);

/*
 * One received EAPOL frame (802.1X header on).  Returns:
 *   <0 drop (bad / replayed / not for us), 0 nothing to send,
 *   >0 length of the reply written to out (send it to aa); *done |= WPA_PTK / WPA_GTK when
 *   keys in *k are new and must be installed (PTK before sending M4 is fine on mac80211:
 *   M4 itself goes out unencrypted as it is queued before the key is in use).
 */
#define WPA_PTK 1
#define WPA_GTK 2
int wpa_rx(struct wpa *w, const uint8_t *frame, size_t len, uint8_t *out, size_t out_size,
	   struct wpa_keys *k, int *done, int (*rand)(uint8_t *, size_t));

/* building blocks (exported for tests) */
void wpa_prf_sha1(const uint8_t *key, size_t klen, const char *label, const uint8_t *data, size_t dlen,
		  uint8_t *out, size_t olen);
void wpa_kdf_sha256(const uint8_t *key, size_t klen, const char *label, const uint8_t *data, size_t dlen,
		    uint8_t *out, size_t olen);
int wpa_aes_unwrap(const uint8_t *kek, const uint8_t *in, size_t len, uint8_t *out);
void wpa_aes_wrap(const uint8_t *kek, const uint8_t *in, size_t len, uint8_t *out);
void wpa_mic(int ver, const uint8_t *kck, const uint8_t *data, size_t len, uint8_t mic[16]);
#endif
