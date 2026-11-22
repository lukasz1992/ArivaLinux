#!/bin/bash
# 00: fetching sources (with sha256 verification). Idempotent.
. "$(dirname "$0")/lib.sh"; need curl sha256sum
fetch "https://cdn.kernel.org/pub/linux/kernel/projects/cip/4.4/linux-cip-$CIP_VER.tar.xz" "linux-cip-$CIP_VER.tar.xz"
fetch "https://busybox.net/downloads/busybox-$BUSYBOX_VER.tar.bz2" "busybox-$BUSYBOX_VER.tar.bz2"
fetch "https://bearssl.org/bearssl-$BEARSSL_VER.tar.gz" "bearssl-$BEARSSL_VER.tar.gz"
fetch "https://github.com/richfelker/musl-cross-make/archive/$MCM_COMMIT.tar.gz" "musl-cross-make-${MCM_COMMIT:0:7}.tar.gz"
FW="https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain"
for f in $(awk '$2 ~ /^firmware\//{print $2}' "$SDK_ROOT/scripts/checksums.sha256"); do
    fetch "$FW/${f#firmware/}?id=$FIRMWARE_TAG" "$f"
done
log "sources in $DL_DIR OK"
