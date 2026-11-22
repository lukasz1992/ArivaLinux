# patches/

The kernel changes are the numbered series in `patches/kernel/`, applied in order onto the pristine CIP 4.4.302-cip115
tree (`scripts/30-kernel.sh` does it; `git apply` per patch).  Rules: **no binaries** (busybox is built, firmware comes
from linux-firmware), **minimal** (`-U2 --minimal`), **at most one driver per patch**, and everything that differs
between boards lives in a board file (`arch/mips/ali-c3503d/board-*.c`, selected by a Kconfig choice), never in the SoC
code.  Adding a board means: one new `board-<name>.c`, one Kconfig entry, one defconfig, and (if its remote or panel
differ) a keymap/driver patch of its own.

```sh
# regenerate after changes (in a kernel tree whose base commit is `pristine`):
git format-patch -U2 --minimal --no-signature pristine..HEAD -o patches/kernel/
```

| patch | subject |
|---|---|
| 0001 | mips: tlb-r4k: make the CIP TLB-uniquify backport build on 4.4 |
| 0002 | mips: introduce MIPS_NOMMU (CONFIG_MMU=n) skeleton: P1 |
| 0003 | mips: nommu headers (pgtable_no, uaccess_no, generic mm hooks): P2 |
| 0004 | mips: gate TLB/page-table/vdso machinery out of nommu build: P3 |
| 0005 | mips: run userland in kernel mode (entry rework): P5 |
| 0006 | fs, mips: allow BINFMT_ELF_FDPIC on MIPS nommu: P6 |
| 0007 | mips nommu: /dev/mem mmap hands out the KSEG1 view (busybox devmem) |
| 0008 | mips nommu: FDPIC userland fixes (elf.h, binfmt_elf_fdpic, process) |
| 0009 | mips: add ALi C3503D SoC platform (boot, console, memory, timer) |
| 0010 | mips: ali-c3503d: ALi INTC (IP3 cascade) |
| 0011 | mips: ali-c3503d: USB wrapper/PHY initialisation and EHCI device |
| 0012 | mtd: ali-sflash: ALi C3503D SPI NOR controller |
| 0013 | fbdev: ali-gma: ALi C3503D OSD framebuffer (two GMA layers) |
| 0014 | media: rc: ali-ir: ALi M6303 IR receiver |
| 0015 | media: rc: keymap for the Ferguson RCU540 remote |
| 0016 | auxdisplay: fd650: FD650K/TM1650 front-panel driver |
| 0017 | mips: ali-c3503d: GPIO banks |
| 0018 | mips: ali-c3503d: watchdog |
| 0019 | mips: ali-c3503d: RTC |
| 0020 | i2c: ali-scb: ALi SCB I2C master (two controllers) |
| 0021 | mips: ali-c3503d: OTP fuses (read-only sysfs file) |
| 0022 | mips: ali-c3503d: debugfs register script interpreter (ali/regs) |
| 0023 | mips: ali-c3503d: Ferguson Ariva 54 board |
| 0024 | mips: ali-c3503d: built-in initramfs from the SDK rootfs tree |
| 0025 | mips: add ali_ariva54_defconfig |

`patches/optional/` holds patches that are not part of the image: `dev-watchdog-feeder.patch` (a kernel timer feeds the
watchdog, so a hang resets the box; timeout in `/sys/module/dev_watchdog/parameters/timeout`, default 5 s; development only) and `mac80211-station-only-no-legacy-ciphers.patch`.
Pass them with `EXTRA_PATCHES=...` to `scripts/30-kernel.sh`; `EXTRA_FRAG=configs/debug.frag` adds the matching development kernel configuration (verbose boot, panic on oops).
