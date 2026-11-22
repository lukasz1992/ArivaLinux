#!/bin/bash
# Host tests of the WPA2 core (wpa.c): 802.11/RFC vectors + a real handshake from a public sample
# from Wireshark (wpa-Induction.pcap: SSID "Coherer", password "Induction"), simulated AP (GTK rekey, MIC, replay).
# Usage: userspace/networkd/test-host.sh   (works in /dev/shm/networkd-test)
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; SDK="$H/../.."; . "$SDK/sdk.conf"
W=/dev/shm/networkd-test; mkdir -p "$W"; cd "$W"
PCAP_URL="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/wpa-Induction.pcap"
PCAP_SHA=2b57dca7fa2c3bd0e942060b546028d961bfb698fb12ed8b2947b13f88d170c8
[ -f wpa-Induction.pcap ] || curl -sfL -m 60 "$PCAP_URL" -o wpa-Induction.pcap
echo "$PCAP_SHA  wpa-Induction.pcap" | sha256sum -c --quiet
python3 -I - <<'PY'
import struct
d=open("wpa-Induction.pcap","rb").read(); p=24; out=b""
while p+16<=len(d):
    cl=struct.unpack("<I",d[p+8:p+12])[0]; pkt=d[p+16:p+16+cl]; p+=16+cl
    f=pkt[struct.unpack("<H",pkt[2:4])[0]:]; k=f.find(bytes.fromhex("aaaa03000000888e"))
    if k<0: continue
    e=f[k+8:]; e=e[:struct.unpack(">H",e[2:4])[0]+4]; out+=struct.pack("<H",len(e))+e
open("eapol.bin","wb").write(out)
PY
if [ ! -f bearssl-$BEARSSL_VER/libbearssl.a ]; then
    tar -xzf "$SDK/$DL_DIR/bearssl-$BEARSSL_VER.tar.gz" 2>/dev/null || tar -xzf "$DL_DIR/bearssl-$BEARSSL_VER.tar.gz"
    ( cd bearssl-$BEARSSL_VER && mkdir -p o && for c in $(find src -name '*.c'); do cc -O2 -c -Iinc -Isrc "$c" -o "o/$(echo "$c" | tr / _).o"; done && ar rcs libbearssl.a o/*.o )
fi
cc -Wall -Wextra -I"$H" -Ibearssl-$BEARSSL_VER/inc -o test_wpa "$H/test_wpa.c" "$H/wpa.c" bearssl-$BEARSSL_VER/libbearssl.a
./test_wpa eapol.bin
