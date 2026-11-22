# networkd: network manager (SDK: scripts/20-userspace.sh -> make CC=... OUT=... BEARSSL=... install)
CC ?= cc
OUT ?= .
BEARSSL ?= ../../dl/bearssl
SRC = networkd.c wpa.c nl.c netcfg.c dhcp.c
networkd: $(SRC) wpa.h nl.h netcfg.h dhcp.h
	$(CC) -Wall -Wextra -I$(BEARSSL)/inc -o $@ $(SRC) $(BEARSSL)/libbearssl.a
install: networkd
	cp networkd $(OUT)/networkd
# host tests of the WPA2 core: make test HOSTBEARSSL=<bearssl built with gcc> EAPOL=<eapol.bin>
test: test_wpa.c wpa.c wpa.h
	cc -Wall -Wextra -I. -I$(HOSTBEARSSL)/inc -o test_wpa test_wpa.c wpa.c $(HOSTBEARSSL)/libbearssl.a
	./test_wpa $(EAPOL)
clean:
	rm -f networkd test_wpa
.PHONY: install test clean
