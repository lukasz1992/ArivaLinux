#!/bin/bash
# 20: userspace (static PIE, musl): busybox, programs from userspace/*/ + rootfs/skeleton -> $OUT_DIR/rootfs (initramfs tree)
# Note: initramfs is compiled into vmlinux, so this stage precedes 30-kernel.sh.
. "$(dirname "$0")/lib.sh"; need make tar bzip2 readelf openssl
"$SDK_ROOT/scripts/00-fetch.sh"; make_cc
R="$OUT_DIR/rootfs"; rm -rf "$R"; mkdir -p "$R/bin"
src="$BUILD_DIR/busybox-$BUSYBOX_VER"; rm -rf "$src"; mkdir -p "$BUILD_DIR"
tar -xjf "$DL_DIR/busybox-$BUSYBOX_VER.tar.bz2" -C "$BUILD_DIR"
cd "$src"
make -s defconfig >/dev/null; merge_frag .config "$SDK_ROOT/configs/busybox.frag"; (set +o pipefail; yes "" | make -s oldconfig >/dev/null)
make -j"$JOBS" CROSS_COMPILE="$TC/bin/$MUSL_PREFIX" CC="$SDK_CC" AR="$TC/bin/${MUSL_PREFIX}gcc-ar" HOSTCC=gcc busybox >"$BUILD_DIR/busybox.log" 2>&1 \
    || { tail -30 "$BUILD_DIR/busybox.log"; die "busybox: build error"; }
cp busybox "$R/bin/busybox"
# BearSSL (static library for programs from userspace/)
BS="$BUILD_DIR/bearssl-$BEARSSL_VER"; rm -rf "$BS"; tar -xzf "$DL_DIR/bearssl-$BEARSSL_VER.tar.gz" -C "$BUILD_DIR"
( cd "$BS" && for c in $(find src -name '*.c'); do o="obj/${c#src/}"; o="${o%.c}.o"; mkdir -p "${o%/*}"
      "$SDK_CC" -c -Iinc -Isrc "$c" -o "$o" || exit 1; done && "$TC/bin/${MUSL_PREFIX}ar" rcs libbearssl.a $(find obj -name '*.o') ) \
    || die "BearSSL: build error"
for d in "$SDK_ROOT"/userspace/*/; do
    [ -f "$d/Makefile" ] || continue
    log "userspace: $(basename "$d")"
    make -C "$d" CC="$SDK_CC" OUT="$R/bin" BEARSSL="$BS" install && make -C "$d" clean >/dev/null
done
check_static_pie "$R"/bin/*
"$SDK_ROOT/scripts/verify-isa.sh" "$R"/bin/* || die "userspace contains instructions outside MIPS32 R1 / FPU"
[ "$(qemu-mipsel -cpu 4Kc "$R/bin/busybox" echo ALiLinux)" = "ALiLinux" ] || die "busybox does not work in qemu 4Kc"
# strip: the binaries live in RAM (initramfs); the checks above ran on the unstripped files
"$TC/bin/${MUSL_PREFIX}strip" --strip-unneeded "$R"/bin/busybox "$R"/bin/networkd || die "strip failed"
[ "$(qemu-mipsel -cpu 4Kc "$R/bin/busybox" echo ALiLinux)" = "ALiLinux" ] || die "busybox does not work in qemu 4Kc after strip"
# initramfs tree: skeleton, links for applets invoked by path (exec from init/telnetd and from the kernel),
# empty directories, /etc/shadow (SHA-512 hash; salt derived from the password = reproducible image)
cp -a "$SDK_ROOT/rootfs/skeleton/." "$R/"
[ ! -d "$BOARD_DIR/rootfs" ] || cp -a "$BOARD_DIR/rootfs/." "$R/"      # board overlay (files only this board has)
printf '%s\n' "${BOARD_HOSTNAME:-alilinux}" > "$R/etc/hostname"             # generated at build time, not a fixed file
for a in sh login reboot mount umount; do ln -s busybox "$R/bin/$a"; done
mkdir -p "$R/proc" "$R/sys" "$R/dev" "$R/mnt" "$R/tmp" "$R/run" "$R/var/log" "$R/root"
chmod -R go-w "$R"; chmod 700 "$R/root"
if [ -n "$ROOT_PASSWORD" ]; then
    salt=$(printf 'alilinux:%s' "$ROOT_PASSWORD" | sha256sum | cut -c1-16)
    hash=$(openssl passwd -6 -salt "$salt" "$ROOT_PASSWORD")
else
    hash=""                                  # empty field: busybox login does not ask for a password
fi
printf 'root:%s:20000:0:99999:7:::\n' "$hash" > "$R/etc/shadow"
chmod 600 "$R/etc/shadow"
log "rootfs OK: $(cd "$R" && find . -type f | sort | tr '\n' ' ')"
