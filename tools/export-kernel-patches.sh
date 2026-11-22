#!/bin/bash
# Export a kernel series (commits on top of `pristine`) into the SDK:
#   patches/kernel/            common patches (SoC, generic drivers)
#   boards/<board>/patches/    the board-specific ones, recognised by subject (keymap, board file, defconfig)
# usage: export-kernel-patches.sh KERNEL_TREE [BOARD]
set -euo pipefail
K=${1:?kernel tree}; BOARD=${2:-ferguson-ariva54}
SDK="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
git -C "$K" format-patch -q -U2 --minimal --no-signature pristine..HEAD -o "$T"
rm -rf "$SDK/patches/kernel" "$SDK/boards/$BOARD/patches"; mkdir -p "$SDK/patches/kernel" "$SDK/boards/$BOARD/patches"
n=0; m=0
for f in "$T"/0*.patch; do
    b=$(basename "$f"); name=${b#*-}
    case "$b" in
        *keymap-for-the-Ferguson*|*Ferguson-Ariva-54-board*|*ali_ariva54_defconfig*)
            m=$((m+1)); dst="$SDK/boards/$BOARD/patches/$(printf %04d $m)-$name" ;;
        *) n=$((n+1)); dst="$SDK/patches/kernel/$(printf %04d $n)-$name" ;;
    esac
    sed -e '1s/^From [0-9a-f]* /From 0000000000000000000000000000000000000000 /' -e 's/^Subject: \[PATCH [0-9]*\/[0-9]*\]/Subject: [PATCH]/' "$f" > "$dst"
done
echo "exported: $n common, $m for $BOARD"
