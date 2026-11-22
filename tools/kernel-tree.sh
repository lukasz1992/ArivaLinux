#!/bin/bash
# kernel-tree.sh DIR [BOARD] - a git tree of the kernel to work on the patches.
# Unpacks the pristine CIP tree, commits it as `pristine`, and applies patches/kernel/ and boards/<BOARD>/patches/ as commits
# (git am), so each patch is one commit.  Change/rebase the commits, then write the series back with
#   tools/export-kernel-patches.sh DIR [BOARD]
. "$(dirname "$0")/../scripts/lib.sh"; need git tar xz
DIR=${1:?usage: kernel-tree.sh DIR [BOARD]}; BOARD=${2:-$BOARD}
BDIR="$SDK_ROOT/boards/$BOARD"; [ -d "$BDIR/patches" ] || die "unknown board $BOARD"
[ ! -e "$DIR/.git" ] || die "$DIR already holds a git tree"
"$SDK_ROOT/scripts/00-fetch.sh"
mkdir -p "$DIR"; tar -xJf "$DL_DIR/linux-cip-$CIP_VER.tar.xz" -C "$DIR" --strip-components=1
cd "$DIR"
git init -q; git config user.name "${GIT_AUTHOR_NAME:-ALiLinux SDK}"; git config user.email "${GIT_AUTHOR_EMAIL:-sdk@localhost}"
git add -A; git commit -q -m "pristine: linux-cip-$CIP_VER"; git branch pristine
for p in "$SDK_ROOT"/patches/kernel/0*.patch "$BDIR"/patches/0*.patch; do
    git am -q --whitespace=nowarn "$p" || die "git am failed: $(basename "$p")"
done
log "kernel tree $DIR: $(git rev-list --count pristine..HEAD) patches applied on pristine"
