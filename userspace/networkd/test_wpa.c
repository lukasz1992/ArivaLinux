/*
 * test_wpa.c - host tests of the WPA2 core (wpa.c):
 *   - IEEE 802.11 Annex J vectors: PBKDF2 PMK, PRF-SHA1; RFC 3394 AES key wrap; RFC 4493 AES-CMAC;
 *   - a real 4-way handshake (Wireshark sample wpa-Induction.pcap, SSID "Coherer", passphrase
 *     "Induction"; frames extracted to eapol.bin: u16 length + EAPOL frame, M1..M4): wpa_rx() fed
 *     with the captured M1 / M3 must produce the captured M2 / M4 byte for byte;
 *   - a simulated AP: group key rekey (1/2 -> 2/2), replay and bad-MIC rejection.
 * Build: cc -I. -I$BEARSSL/inc test_wpa.c wpa.c $BEARSSL/libbearssl.a ; run: ./a.out eapol.bin
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wpa.h"

static int fails;
#define CHECK(c, what) do { if (c) printf("OK    %s\n", what); else { printf("FAIL  %s\n", what); fails++; } } while (0)

static void hex(const char *s, uint8_t *o) { while (*s) { unsigned v; sscanf(s, "%2x", &v); *o++ = (uint8_t)v; s += 2; } }
static int eqhex(const uint8_t *b, const char *s) { uint8_t t[128]; hex(s, t); return !memcmp(b, t, strlen(s) / 2); }

static uint8_t fixed_snonce[32];
static int rnd_fixed(uint8_t *b, size_t n) { memcpy(b, fixed_snonce, n); return 0; }
static int rnd_simple(uint8_t *b, size_t n) { size_t i; for (i = 0; i < n; i++) b[i] = (uint8_t)(i * 7 + 3); return 0; }

int main(int argc, char **argv)
{
	uint8_t pmk[32], out[64], b[256], w2[24];
	FILE *f;

	/* --- vectors --- */
	wpa_pmk("password", (const uint8_t *)"IEEE", 4, pmk);
	CHECK(eqhex(pmk, "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"), "PBKDF2 PMK (802.11 J.4)");
	memset(b, 0x0b, 20);
	wpa_prf_sha1(b, 20, "prefix", (const uint8_t *)"Hi There", 8, out, 64);
	CHECK(eqhex(out, "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee"
			 "75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"), "PRF-512 SHA1 (802.11 J.3)");
	hex("000102030405060708090a0b0c0d0e0f", b);
	hex("00112233445566778899aabbccddeeff", b + 16);
	wpa_aes_wrap(b, b + 16, 16, w2);
	CHECK(eqhex(w2, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"), "AES key wrap (RFC 3394 4.1)");
	CHECK(!wpa_aes_unwrap(b, w2, 24, out) && !memcmp(out, b + 16, 16), "AES key unwrap");
	w2[3] ^= 1;
	CHECK(wpa_aes_unwrap(b, w2, 24, out) != 0, "AES unwrap rejects corrupted data");
	hex("2b7e151628aed2a6abf7158809cf4f3c", b);
	wpa_mic(3, b, NULL, 0, out);
	CHECK(eqhex(out, "bb1d6929e95937287fa37d129b756746"), "AES-CMAC empty (RFC 4493)");
	hex("6bc1bee22e409f96e93d7e117393172a", b + 16);
	wpa_mic(3, b, b + 16, 16, out);
	CHECK(eqhex(out, "070a16b46b4d4144f79bdd9dd04a287c"), "AES-CMAC 16 B (RFC 4493)");

	/* --- the captured handshake --- */
	if (argc > 1 && (f = fopen(argv[1], "rb"))) {
		static uint8_t fr[4][512];
		size_t fl[4];
		uint8_t lb[2], r[512];
		struct wpa w;
		struct wpa_keys k;
		int i, n, done;

		for (i = 0; i < 4; i++) {
			if (fread(lb, 1, 2, f) != 2) break;
			fl[i] = (size_t)(lb[0] | lb[1] << 8);
			if (fread(fr[i], 1, fl[i], f) != fl[i]) break;
		}
		fclose(f);
		memset(&w, 0, sizeof(w));
		memset(&k, 0, sizeof(k));
		wpa_pmk("Induction", (const uint8_t *)"Coherer", 7, w.pmk);
		hex("000c4182b255", w.aa);
		hex("000d9382363a", w.spa);
		w.akm = WPA_AKM_PSK;
		memcpy(fixed_snonce, fr[1] + 4 + 13, 32);			/* SNonce from M2 */
		w.ie_len = fr[1][4 + 93] << 8 | fr[1][4 + 94];
		memcpy(w.ie, fr[1] + 4 + 95, (size_t)w.ie_len);			/* our RSN IE as captured */
		/* this 2006 station sets Key Length = 16 in M2/M4 (802.11-2016 and wpa_supplicant: 0);
		 * the MIC covers it, so put the captured value in and re-MIC with our KCK */
#define AS_CAPTURED(r, n, cap, kck) do { (r)[7] = (cap)[7]; (r)[8] = (cap)[8]; memset((r) + 81, 0, 16); \
	wpa_mic(2, (kck), (r), (size_t)(n), (r) + 81); } while (0)
		n = wpa_rx(&w, fr[0], fl[0], r, sizeof(r), &k, &done, rnd_fixed);
		if (n > 0) AS_CAPTURED(r, n, fr[1], w.t_kck);		/* M2: the PTK is still pending (TPTK) */
		CHECK(n == (int)fl[1] && !memcmp(r, fr[1], fl[1]), "capture: M1 -> M2 byte for byte (PTK, MIC)");
		n = wpa_rx(&w, fr[2], fl[2], r, sizeof(r), &k, &done, rnd_fixed);
		if (n > 0) AS_CAPTURED(r, n, fr[3], w.kck);		/* M4: committed by the verified M3 */
		printf("      M3: GTK idx %d, %d bytes\n", k.gtk_idx, k.gtk_len);
		CHECK(n == (int)fl[3] && !memcmp(r, fr[3], fl[3]), "capture: M3 (MIC, GTK unwrap) -> M4 byte for byte");
		CHECK(done == (WPA_PTK | WPA_GTK) && k.have_ptk && k.have_gtk && (k.gtk_len == 16 || k.gtk_len == 32), "capture: PTK + GTK to install");
		CHECK(wpa_rx(&w, fr[2], fl[2], r, sizeof(r), &k, &done, rnd_fixed) < 0, "capture: replayed M3 rejected");
	} else {
		printf("SKIP  captured handshake (no eapol.bin)\n");
	}

	/* --- simulated AP: full 4-way + group rekey, MIC checks --- */
	{
		struct wpa s, ap;	/* ap: authenticator side computed with the same primitives */
		struct wpa_keys k;
		uint8_t m[512], r[512], gtk[16], kd[64], enc[72], tk_ap[48], d[76];
		int n, done, len;
		uint64_t rc = 1;

		memset(&s, 0, sizeof(s)); memset(&k, 0, sizeof(k)); memset(&ap, 0, sizeof(ap));
		wpa_pmk("secret-pass", (const uint8_t *)"TestNet", 7, s.pmk);
		hex("020000000001", s.aa); hex("020000000002", s.spa);
		s.akm = WPA_AKM_PSK; s.ie_len = wpa_rsn_ie(s.ie, WPA_AKM_PSK, 1, 0);
#define MK(info, dlen) do { memset(m, 0, sizeof(m)); len = 4 + 95 + (dlen); m[0] = 2; m[1] = 3; \
	m[2] = (uint8_t)((len - 4) >> 8); m[3] = (uint8_t)(len - 4); m[4] = 2; m[5] = (uint8_t)((info) >> 8); \
	m[6] = (uint8_t)(info); m[16] = (uint8_t)rc++; m[97] = (uint8_t)((dlen) >> 8); m[98] = (uint8_t)(dlen); } while (0)
		/* M1 */
		MK(0x008a, 0);
		memset(m + 17, 0x55, 32);
		n = wpa_rx(&s, m, (size_t)len, r, sizeof(r), &k, &done, rnd_simple);
		/* AP side: derive PTK from its view and check the M2 MIC */
		memcpy(d, s.aa, 6); memcpy(d + 6, s.spa, 6);			/* aa < spa */
		memset(d + 12, 0x55, 32); memcpy(d + 44, r + 17, 32);		/* anonce(0x55..) vs snonce */
		if (memcmp(d + 12, d + 44, 32) > 0) { uint8_t t[32]; memcpy(t, d + 12, 32); memcpy(d + 12, d + 44, 32); memcpy(d + 44, t, 32); }
		wpa_prf_sha1(s.pmk, 32, "Pairwise key expansion", d, 76, tk_ap, 48);
		{
			uint8_t z[512], mic[16];
			memcpy(z, r, (size_t)n); memset(z + 81, 0, 16);
			wpa_mic(2, tk_ap, z, (size_t)n, mic);
			CHECK(n > 0 && !memcmp(mic, r + 81, 16), "sim AP: M2 MIC valid with AP-derived KCK");
		}
		/* M3 with GTK KDE, encrypted with KEK */
		memset(gtk, 0x77, 16);
		kd[0] = 0xdd; kd[1] = 22; kd[2] = 0; kd[3] = 0x0f; kd[4] = 0xac; kd[5] = 1; kd[6] = 1; kd[7] = 0;
		memcpy(kd + 8, gtk, 16);
		memcpy(kd + 24, s.ie, (size_t)s.ie_len);			/* plus our RSN IE copy */
		{
			int pl = 24 + s.ie_len; if (pl % 8) kd[pl++] = 0xdd; while (pl % 8) kd[pl++] = 0;
			wpa_aes_wrap(tk_ap + 16, kd, (size_t)pl, enc);
			MK(0x13ca, pl + 8);
			memset(m + 17, 0x55, 32); memcpy(m + 99, enc, (size_t)pl + 8);
		}
		{ uint8_t mic[16]; wpa_mic(2, tk_ap, m, (size_t)len, mic); memcpy(m + 81, mic, 16); }
		n = wpa_rx(&s, m, (size_t)len, r, sizeof(r), &k, &done, rnd_simple);
		CHECK(n > 0 && done == (WPA_PTK | WPA_GTK) && !memcmp(k.tk, tk_ap + 32, 16) && !memcmp(k.gtk, gtk, 16) && k.gtk_idx == 1,
		      "sim AP: M3 -> M4, TK and GTK (idx 1) match");
		/* group rekey 1/2 */
		memset(gtk, 0x99, 16); kd[6] = 2; memcpy(kd + 8, gtk, 16); kd[24] = 0xdd; kd[25] = 0; kd[26] = kd[27] = kd[28] = kd[29] = kd[30] = kd[31] = 0;
		wpa_aes_wrap(tk_ap + 16, kd, 32, enc);
		MK(0x1382, 40);
		memcpy(m + 99, enc, 40);
		{ uint8_t mic[16]; wpa_mic(2, tk_ap, m, (size_t)len, mic); memcpy(m + 81, mic, 16); }
		n = wpa_rx(&s, m, (size_t)len, r, sizeof(r), &k, &done, rnd_simple);
		CHECK(n > 0 && done == WPA_GTK && !memcmp(k.gtk, gtk, 16) && k.gtk_idx == 2, "sim AP: group rekey 1/2 -> 2/2, new GTK idx 2");
		m[81] ^= 1; m[16] = (uint8_t)rc++;
		CHECK(wpa_rx(&s, m, (size_t)len, r, sizeof(r), &k, &done, rnd_simple) < 0, "sim AP: bad MIC rejected");
		/* a forged M1 (no MIC, replay counter all ones) must not break the live keys or the counter:
		 * the next genuine group rekey still has to verify */
		MK(0x008a, 0);
		memset(m + 9, 0xff, 8); memset(m + 17, 0xaa, 32);
		wpa_rx(&s, m, (size_t)len, r, sizeof(r), &k, &done, rnd_simple);
		memset(gtk, 0x33, 16); kd[6] = 3; memcpy(kd + 8, gtk, 16);
		wpa_aes_wrap(tk_ap + 16, kd, 32, enc);
		MK(0x1382, 40);
		memcpy(m + 99, enc, 40);
		{ uint8_t mic[16]; wpa_mic(2, tk_ap, m, (size_t)len, mic); memcpy(m + 81, mic, 16); }
		n = wpa_rx(&s, m, (size_t)len, r, sizeof(r), &k, &done, rnd_simple);
		CHECK(n > 0 && done == WPA_GTK && !memcmp(k.gtk, gtk, 16) && k.gtk_idx == 3, "sim AP: forged M1 does not break the next rekey");
	}
	{
		uint8_t ie[32]; int akm, c, rq;
		int l = wpa_rsn_ie(ie, WPA_AKM_PSK, 1, 0);
		CHECK(!wpa_rsn_parse(ie, l, &akm, &c, &rq) && akm == WPA_AKM_PSK && c == 1 && rq == 0, "RSN IE build/parse");
		ie[7] = 2;	/* group TKIP */
		CHECK(wpa_rsn_parse(ie, l, &akm, &c, &rq) < 0, "RSN IE with TKIP group rejected");
	}
	printf("%s (%d failed)\n", fails ? "FAIL" : "PASS", fails);
	return fails != 0;
}
