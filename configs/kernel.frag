# Overlay on ali_ariva54_defconfig (scripts/30-kernel.sh, merge_config.sh).
# Firmware: not built into the kernel.  scripts/pack-modules.py copies the files a shipped module names in its modinfo
# (rt2870.bin, mt7601u.bin, rtlwifi/*.bin) into the initramfs /lib/firmware, where the kernel's own file loader finds them.
# CONFIG_EXTRA_FIRMWARE is empty.
# WiFi: RT5370 (rt2800usb), the RTL8xxx USB dongles (rtl8xxxu; 4.4 has no RTL8192EU) and MT7601U, all modules (see "Driver modules")
CONFIG_RT2800USB_RT53XX=y
# no mesh; no built-in regulatory database (world domain + beacon hints)
# (optional patch: patches/optional/mac80211-station-only-no-legacy-ciphers.patch)
# CONFIG_MAC80211_MESH is not set
# CONFIG_CFG80211_INTERNAL_REGDB is not set
# /dev/i2c-N: busybox i2cdetect/i2cget/i2cset for tuner bring-up (M3031 on SCB1) and EEPROM
CONFIG_I2C_CHARDEV=y
# /dev/kmem (writing to kernel memory through kernel pointers) is unnecessary; /dev/mem is enough for devmem
# CONFIG_DEVKMEM is not set
# AF_PACKET: networkd (DHCP and EAPOL/WPA2 client) - without it only static IP and open networks
CONFIG_PACKET=y

# DVB: no dvb_net (IP-over-DVB); the symbol defaults to y with NET && INET, so it is disabled explicitly
# CONFIG_DVB_NET is not set

# SMALL_FLASH (model: OpenWrt config/Config-kernel.in): -Os, no AIO, ELF core dumps or seccomp.
# KALLSYMS (~210 KB of symbol tables) is off; configs/debug.frag turns it back on for readable oopses.
# CONFIG_KALLSYMS is not set
CONFIG_CC_OPTIMIZE_FOR_SIZE=y
# CONFIG_AIO is not set
# CONFIG_ELF_CORE is not set
# CONFIG_SECCOMP is not set

# No PS/2 controller in the SoC: i8042 reaches ports 0x60/0x64 via mips_io_port_base and on hardware boot hangs here
# (the log stops at "calling i8042_init"; measured on the box 2026-11-21).  KEYBOARD_ATKBD does "select SERIO_I8042",
# so the AT keyboard and PS/2 mouse must be disabled too (the set-top box has an IR remote, not PS/2).
# CONFIG_SERIO_I8042 is not set
# CONFIG_KEYBOARD_ATKBD is not set
# CONFIG_MOUSE_PS2 is not set

# Kernel modules (2026-11-22): /proc/modules, busybox insmod/rmmod.  On nommu MIPS module_alloc is the generic vmalloc_exec
# (MODULE_START is not defined), R_MIPS_26 jumps fit in a single KSEG0 segment.  No symbol versioning.
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set

# IPv6 removed entirely (decision 2026-11-22): no sit0 and ADDRCONF, smaller image; networkd and busybox use IPv4 only
# CONFIG_IPV6 is not set

# debugfs: ali/regs register interpreter (bring-up)
CONFIG_DEBUG_FS=y

# Driver modules (2026-11-22): only the WiFi stack is modular.  The modules live in the initramfs and are loaded from
# /etc/modules by /etc/init.d/S05modules; the .ko files of loaded modules can be deleted afterwards to give the RAM back
# (boards/<board>/modules.list decides what is shipped and what is loaded).  Everything else stays built in: USB mass
# storage and its file system (FAT/VFAT, NLS), the ALi drivers (flash, GMA, IR, front panel).
CONFIG_CFG80211=m
CONFIG_MAC80211=m
CONFIG_RT2X00=m
CONFIG_RT2800USB=m
CONFIG_RTL8XXXU=m
CONFIG_WL_MEDIATEK=y
CONFIG_MT7601U=m
