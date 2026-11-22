#!/bin/bash
# 95: final set: copies the deliverables of a build into $DIST_DIR (default dist/), apart from the work files in out/
#   vmlinux.bin, vmlinux, System.map, kernel.config   the kernel
#   maincode.abs                                       the maincode chunk to flash at 0x130000 (loader shell / a54 tools)
#   BUILD-INFO, SHA256SUMS
. "$(dirname "$0")/lib.sh"; need sha256sum
K="$OUT_DIR/kernel"
for f in "$K/vmlinux.bin" "$K/vmlinux" "$K/System.map" "$K/.config" "$OUT_DIR/maincode.abs"; do
    [ -f "$f" ] || die "missing $f — run the earlier stages (scripts/run-all.sh)"
done
rm -rf "$DIST_DIR"; mkdir -p "$DIST_DIR"
cp "$K/vmlinux.bin" "$K/vmlinux" "$K/System.map" "$DIST_DIR/"
cp "$K/.config" "$DIST_DIR/kernel.config"
cp "$OUT_DIR/maincode.abs" "$DIST_DIR/"
{
    echo "ALiLinux SDK build $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "sdk:      $(git -C "$SDK_ROOT" describe --always --dirty 2>/dev/null || echo 'not a git checkout')"
    echo "board:    $BOARD"
    echo "kernel:   CIP $CIP_VER + $(ls "$SDK_ROOT"/patches/kernel/0*.patch | wc -l) common + $(ls "$BOARD_DIR"/patches/0*.patch | wc -l) board patches, defconfig $BOARD_DEFCONFIG"
    echo "busybox:  $BUSYBOX_VER"
    echo "image:    maincode chunk (span $MAINCODE_SPAN)"
} > "$DIST_DIR/BUILD-INFO"
( cd "$DIST_DIR" && sha256sum $(ls | grep -v -e SHA256SUMS) > SHA256SUMS )
log "final set in $DIST_DIR:"; ls -l "$DIST_DIR" | tail -n +2
