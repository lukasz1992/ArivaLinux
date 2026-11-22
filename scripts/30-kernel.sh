#!/bin/bash
# 30: kernel: CIP + patches/kernel/*.patch (+ EXTRA_PATCHES, EXTRA_FRAG: optional, e.g. diagnostics) + firmware + initramfs (from 20-userspace) -> $OUT_DIR/kernel
. "$(dirname "$0")/lib.sh"; need make tar xz git "${KCROSS}gcc"
"$SDK_ROOT/scripts/00-fetch.sh"
[ -x "$OUT_DIR/rootfs/bin/busybox" ] || die "missing $OUT_DIR/rootfs — run 20-userspace.sh"
B="$BUILD_DIR/linux"; rm -rf "$B"; mkdir -p "$B"
tar -xJf "$DL_DIR/linux-cip-$CIP_VER.tar.xz" -C "$B" --strip-components=1
cd "$B"
for p in "$SDK_ROOT"/patches/kernel/0*.patch "$BOARD_DIR"/patches/0*.patch ${EXTRA_PATCHES:-}; do git apply --whitespace=nowarn "$p" || die "patch does not apply: $(basename "$p")"; done
log "kernel patches: $(ls "$SDK_ROOT"/patches/kernel/0*.patch | wc -l) common + $(ls "$BOARD_DIR"/patches/0*.patch | wc -l) for $BOARD OK"
# initramfs = tree from 20-userspace (rootfs/skeleton + binaries); the kernel sees it through a link
ln -sfn "$OUT_DIR/rootfs" arch/mips/ali-c3503d/rootfs
M=(make ARCH=mips CROSS_COMPILE="$KCROSS" KCFLAGS="$KFLAGS"
   HOSTCFLAGS="-Wall -Wmissing-prototypes -Wstrict-prototypes -O2 -fomit-frame-pointer -std=gnu89 $HOSTFLAGS_EXTRA")
"${M[@]}" -s "$BOARD_DEFCONFIG" >/dev/null
merge_frag .config "$SDK_ROOT/configs/kernel.frag"
[ ! -f "$BOARD_DIR/kernel.frag" ] || merge_frag .config "$BOARD_DIR/kernel.frag"
[ -z "${EXTRA_FRAG:-}" ] || merge_frag .config "$EXTRA_FRAG"   # optional: extra fragment (e.g. configs/debug-early.frag)
# files in out/rootfs belong to the builder: root in the cpio
printf 'CONFIG_INITRAMFS_ROOT_UID=%s\nCONFIG_INITRAMFS_ROOT_GID=%s\n' "$(id -u)" "$(id -g)" > "$BUILD_DIR/uid.frag"
merge_frag .config "$BUILD_DIR/uid.frag"; "${M[@]}" -s olddefconfig >/dev/null
"${M[@]}" -j"$JOBS" >"$BUILD_DIR/kernel.log" 2>&1 || { grep -E 'error|Error' "$BUILD_DIR/kernel.log" | head; die "kernel: build error (log: $BUILD_DIR/kernel.log)"; }
# Modules: built after vmlinux (modpost needs its symbols), the ones the board names go into the initramfs tree
# (/lib/modules, /etc/modules), then vmlinux is relinked so the initramfs holds them.
if grep -q '^CONFIG_MODULES=y' .config; then
    "${M[@]}" -j"$JOBS" modules >>"$BUILD_DIR/kernel.log" 2>&1 || { grep -E 'error|Error' "$BUILD_DIR/kernel.log" | head; die "kernel: modules build error (log: $BUILD_DIR/kernel.log)"; }
    KREL=$("${M[@]}" -s kernelrelease)
    rm -rf "$BUILD_DIR/modroot"
    "${M[@]}" -s modules_install INSTALL_MOD_PATH="$BUILD_DIR/modroot" INSTALL_MOD_STRIP=1 DEPMOD=true >>"$BUILD_DIR/kernel.log" 2>&1 || die "kernel: modules_install failed"
    python3 -I "$SDK_ROOT/scripts/pack-modules.py" "$BUILD_DIR/modroot" "$KREL" "$OUT_DIR/rootfs" "$BOARD_DIR/modules.list" "$DL_DIR/firmware" | sed 's/^/[sdk] /'
    "${M[@]}" -j"$JOBS" >>"$BUILD_DIR/kernel.log" 2>&1 || { grep -E 'error|Error' "$BUILD_DIR/kernel.log" | head; die "kernel: relink error (log: $BUILD_DIR/kernel.log)"; }
fi
K="$OUT_DIR/kernel"; mkdir -p "$K"
${KCROSS}objcopy -O binary vmlinux "$K/vmlinux.bin"; cp vmlinux System.map .config "$K/"
"$SDK_ROOT/scripts/verify-isa.sh" --allow "$SDK_ROOT/configs/isa-allow.txt" --allow-fpu "$K/vmlinux" \
    || die "vmlinux contains R2 instructions outside the configs/isa-allow.txt list"
log "kernel OK: $K/vmlinux.bin ($(stat -c%s "$K/vmlinux.bin") B)"
