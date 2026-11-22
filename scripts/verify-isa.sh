#!/bin/bash
# verify-isa.sh [--allow FILE] [--allow-fpu] ELF...
# Code correctness gate for 4Kc (MIPS32 R1, no FPU, no MIPS16): disassembles executable sections
# as MIPS32 R2 (superset) and reports instructions outside R1. Exit 1 = found (do not fit the CPU).
# rdhwr (TLS pointer in musl) is R2, but the kernel emulates it via an RI exception — counted separately, not an error.
# --allow FILE: regular expressions of function names (one per line) excluded from the scan
#               (e.g. R2 code guarded by a runtime test, never executed on this CPU).
. "$(dirname "$0")/lib.sh"; need awk
allow=/dev/null; fpu_ok=0; files=()
while [ $# -gt 0 ]; do case $1 in --allow) allow=$2; shift 2;; --allow-fpu) fpu_ok=1; shift;; *) files+=("$1"); shift;; esac; done
[ ${#files[@]} -gt 0 ] || die "give an ELF file"
rc=0
for f in "${files[@]}"; do
    out=$(${KCROSS}objdump -d --no-show-raw-insn -m mips:isa32r2 "$f" | awk -v allowf="$allow" '
        BEGIN { while ((getline l < allowf) > 0) if (l != "" && l !~ /^#/) al[n++] = l }
        /^[0-9a-f]+ <.*>:$/ { fn = $2; gsub(/[<>:]/, "", fn); skip = 0
            for (i = 0; i < n; i++) if (fn ~ ("^(" al[i] ")$")) skip = 1; next }
        /^ *[0-9a-f]+:\t/ { if (skip) next; split($0, p, "\t"); m = p[2]; sub(/ .*/, "", m)
            if (m ~ /^(ext|ins|seb|seh|wsbh|rotr|rotrv|ei|di|synci|jr\.hb|jalr\.hb|mfhc[0-9]|mthc[0-9])$/) { r2[fn "\t" m]++; nr2++ }
            else if (m == "rdhwr") nrd++
            else if (m ~ /\.(s|d|w|l|ps)$/ || m ~ /^(lwc1|swc1|ldc1|sdc1|mfc1|mtc1|cfc1|ctc1|bc1[ft]l?|[ls][wd]xc1|c\..*)$/) { fp[fn "\t" m]++; nfp++ } }
        END { printf "R2 %d\nFPU %d\nRDHWR %d\n", nr2, nfp, nrd
              for (k in r2) print "  R2  " k "  x" r2[k]; for (k in fp) print "  FPU " k "  x" fp[k] }')
    nr2=$(echo "$out" | awk '$1=="R2"&&NF==2{print $2}'); nfp=$(echo "$out" | awk '$1=="FPU"&&NF==2{print $2}')
    nrd=$(echo "$out" | awk '$1=="RDHWR"{print $2}')
    log "$(basename "$f"): R2 instructions: $nr2, FPU: $nfp, rdhwr (TLS, emulated by the kernel): $nrd"
    if [ "$nr2" -gt 0 ] || { [ "$nfp" -gt 0 ] && [ $fpu_ok = 0 ]; }; then
        echo "$out" | sed -n '3,40p'; rc=1
    fi
done
exit $rc
