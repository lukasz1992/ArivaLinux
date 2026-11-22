#!/bin/bash
# 90: packing: vmlinux.bin -> maincode.abs (the maincode chunk: 128-byte header + LZMA stream).
# The header layout (span, name, version, time) comes from boards/<board>/board.conf; no flash dump is needed.
. "$(dirname "$0")/lib.sh"; need python3
K="$OUT_DIR/kernel/vmlinux.bin"; [ -f "$K" ] || die "missing $K - run 30-kernel.sh"
python3 -I "$SDK_ROOT/tools/mkabs.py" --board-conf "$BOARD_DIR/board.conf" --kernel "$K" \
    --chunk-out "$OUT_DIR/maincode.abs" --skip-entry-check
( cd "$OUT_DIR" && sha256sum maincode.abs > SHA256SUMS )
log "done: $OUT_DIR/maincode.abs"
