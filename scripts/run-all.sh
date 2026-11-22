#!/bin/bash
# everything: fetch -> toolchain -> userspace -> kernel -> maincode.abs -> dist/
d="$(dirname "$0")"
for s in 00-fetch 10-toolchain 20-userspace 30-kernel 90-abs 95-dist; do "$d/$s.sh" || exit 1; done
