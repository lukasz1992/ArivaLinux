#!/bin/bash
# 10: toolchain musl (userland). Prebuilt ($MUSL_TC) -> sanity test only; missing -> build musl-cross-make.
. "$(dirname "$0")/lib.sh"; need make tar curl readelf qemu-mipsel
selftest() {
    make_cc
    local t="$BUILD_DIR/tc-selftest"; mkdir -p "$t"
    printf '#include <stdio.h>\n#include <math.h>\nint main(int c,char**v){volatile double x=c+0.5; printf("tc-ok %%.1f\\n", sqrt(x*x+1)*2.0); return 0;}\n' > "$t/t.c"
    "$SDK_CC" "$t/t.c" -o "$t/t" -lm
    check_static_pie "$t/t"
    "$SDK_ROOT/scripts/verify-isa.sh" "$t/t" || die "toolchain generates instructions outside MIPS32 R1 / FPU"
    [ "$(qemu-mipsel -cpu 4Kc "$t/t")" = "tc-ok 3.6" ] || die "runtime test (qemu 4Kc, including soft FP) failed"
    log "toolchain $TC: OK (static-PIE, LOAD<=$SDK_PAGE, R1 without FPU, runs in qemu 4Kc)"
}
if have_musl_tc; then selftest; exit 0; fi
log "building musl-cross-make (GCC 16.2 + binutils 2.47 + musl) — this will take a while"
mkdir -p "$BUILD_DIR"
avail=$(df -BG --output=avail "$BUILD_DIR" 2>/dev/null | tail -1 | tr -dc 0-9 || echo 0)
[ "${avail:-0}" -ge 12 ] || die "not enough space in BUILD_DIR=$BUILD_DIR (${avail:-?} GB < 12 GB): point BUILD_DIR to a disk"
"$SDK_ROOT/scripts/00-fetch.sh"
src="$BUILD_DIR/mcm"; rm -rf "$src"; mkdir -p "$src"
tar -xzf "$DL_DIR/musl-cross-make-${MCM_COMMIT:0:7}.tar.gz" -C "$src" --strip-components=1
cp -r "$SDK_ROOT"/toolchain/patches/* "$src/patches/"; cp "$SDK_ROOT"/toolchain/hashes/* "$src/hashes/"
sed -e "s|^OUTPUT = .*|OUTPUT = $MUSL_TC|" -e "s| -march=native -mtune=native||" "$SDK_ROOT/toolchain/config.mak.example" > "$src/config.mak"
cat >> "$src/config.mak" <<EOF
GNU_SITE = https://ftp.gnu.org/gnu
GCC_SITE = https://gcc.gnu.org/pub/gcc/releases
BINUTILS_SITE = https://sourceware.org/pub/binutils/releases
EOF
make -C "$src" -j"$JOBS" && make -C "$src" install
selftest
