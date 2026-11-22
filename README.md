# ALiLinux SDK

Builds a ready-to-flash Linux image for set-top boxes based on the ALi **C3503D** (MIPS32 4Kc, no MMU):
Linux 4.4.302-cip115 in a no-MMU configuration with a static-PIE musl userland (busybox, a small WiFi/DHCP daemon).
Supported boards live in `boards/`; today that is the **Ferguson Ariva 54** (`boards/ferguson-ariva54`).

## Quick start

```sh
scripts/run-all.sh                                   # fetch -> toolchain -> userspace -> kernel -> abs -> dist/
BOARD=ferguson-ariva54 scripts/run-all.sh            # the same, board named explicitly (the default)
```

Everything the build produces for a board ends in **`dist/<board>/`**:

| file | what |
|---|---|
| `maincode.abs` | the maincode chunk (header + LZMA kernel); flash at 0x130000 through the loader shell |
| `vmlinux.bin`, `vmlinux`, `System.map`, `kernel.config` | the kernel |
| `BUILD-INFO`, `SHA256SUMS` | what was built from what |

The chunk header layout (span, name, version, time) comes from the board's `board.conf`, so no flash dump or vendor
firmware is needed to build.  The boot chain checks every chunk: write only the maincode chunk (and the user
database) to a real box.

Stages can be run one by one (`scripts/00-fetch.sh` ... `95-dist.sh`); each reads the previous stage's output from
`out/<board>/`.  Prerequisites: `make tar xz git curl openssl python3 qemu-user` and the Debian cross compiler
`gcc-mipsel-linux-gnu` (used for the kernel; `scripts/verify-isa.sh` checks that the result is MIPS32 R1, no FPU).

## Layout

| path | contents |
|---|---|
| `sdk.conf` | the one place for configuration: directories, versions, global compiler flags, `BOARD` |
| `scripts/` | stage scripts (`00-fetch`, `10-toolchain`, `20-userspace`, `30-kernel`, `90-abs`, `95-dist`), `lib.sh`, `verify-isa.sh` |
| `toolchain/` | recipe for the musl userland toolchain (musl-cross-make: GCC 16.2, binutils 2.47, musl 1.2.6) and `vfork.S` |
| `patches/kernel/` | common kernel patches: no-MMU MIPS port, the C3503D SoC, its drivers (one driver per patch) |
| `patches/optional/` | development patches, not in the image (`EXTRA_PATCHES=`) |
| `boards/<board>/` | everything specific to one board: `board.conf`, `patches/` (board file, keymap, defconfig), `rootfs/` overlay |
| `configs/` | kernel and busybox configuration fragments |
| `rootfs/skeleton/` | files common to all images (init, inittab, start-up scripts) |
| `userspace/` | own programs (`networkd`) |
| `tools/` | `mkabs.py` (maincode chunk packer), `kernel-tree.sh` (git tree of the kernel with the series applied), `export-kernel-patches.sh` |
| `dl/`, `out/`, `dist/` | download cache, per-board work outputs, final sets (not tracked) |

The toolchain is built once into `out/toolchain` (`TOOLCHAIN_DIR`) and shared by the boards; point `MUSL_TC` at an
existing musl toolchain (prefix `mipsel-linux-musl-`) to skip the build.

## Kernel modules

Only the WiFi stack (`cfg80211`, `mac80211`, `rt2x00*`/`rt2800usb`, `rtl8xxxu`, `mt7601u`) is modular; USB mass storage, FAT and
the ALi drivers are built in.  `30-kernel.sh` builds the kernel twice over: `vmlinux`, then `make modules`, then
`scripts/pack-modules.py` copies the modules named in `boards/<board>/modules.list` (plus their dependencies) into the
initramfs tree and relinks, so modules that a board does not list are not in the image at all.  At boot
`/etc/init.d/S05modules` loads `/etc/modules` with `modprobe`; with `FREE_LOADED=1` in `/etc/modules.conf` the `.ko` files
of the loaded modules are then deleted, which returns their RAM (the initramfs lives in memory).  A `?name` line in
`modules.list` ships a module without loading it (e.g. `modprobe rtl8xxxu` for a dongle plugged in later).

Firmware is not built into the kernel: `pack-modules.py` reads each shipped module's `modinfo` `firmware:` names and copies those files
(fetched with a checksum from linux-firmware) into the initramfs `/lib/firmware`, where the kernel finds them itself.

Loading is automatic: the build keeps `modules.alias`, `S05modules` installs `/sbin/modalias-helper` as the kernel's uevent
helper and walks `/sys` once for devices that are already there, so the module of a plugged-in USB WiFi dongle is
`modprobe`d by its alias (`usb:v148Fp5370...` loads `rt2800usb` and its dependencies).  The kernel is built without
`-fcommon` (it overrides the 4.4 Makefile's `-fno-common` and turns module globals into SCOMMON symbols, which the module
loader cannot relocate); the host tools get `-fcommon` through `HOSTFLAGS_EXTRA` in `sdk.conf`.  `KALLSYMS` is off in the
release (`configs/debug.frag` turns it on) and the userspace binaries are stripped.

## Adding a board

1. In the kernel patches: a `board-<name>.c` defining `struct ali_board` (RAM size, flash partitions, board devices,
   remote keymap), its entry in `arch/mips/ali-c3503d/Kconfig`, a defconfig - as a patch series in
   `boards/<name>/patches/` (see `ferguson-ariva54` for the shape).
2. `boards/<name>/board.conf` (`BOARD_DEFCONFIG`, `BOARD_HOSTNAME`, `MAINCODE_*` chunk layout), `modules.list` and, if needed, a `rootfs/` overlay and a `kernel.frag`.
3. `BOARD=<name> scripts/run-all.sh`.

A driver that a new board needs and the SoC patches do not have goes into `patches/kernel/` as its own patch.

## Kernel patches

See `patches/README.md`.  `tools/kernel-tree.sh DIR` builds a git tree of the kernel with every patch applied as a commit.  The series is kept as commits on top of the pristine CIP tree; `tools/export-kernel-patches.sh
<kernel-tree>` writes it back out and sorts the board patches into `boards/<board>/patches/`.

## Source

Kernel: <https://cdn.kernel.org/pub/linux/kernel/projects/cip/4.4/linux-cip-4.4.302-cip115.tar.xz>
(sha256 in `scripts/checksums.sha256`, as for every other download).
