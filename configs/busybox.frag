# busybox: nommu, static PIE (the -static-pie flag is added by the SDK wrapper: scripts/lib.sh make_cc)
CONFIG_STATIC=n
CONFIG_PIE=n
CONFIG_NOMMU=y
CONFIG_CROSS_COMPILER_PREFIX=""
# MTD: erasing and writing flash partitions (ali-sflash driver)
CONFIG_FLASH_ERASEALL=y
CONFIG_FLASHCP=y
CONFIG_FLASH_LOCK=y
CONFIG_FLASH_UNLOCK=y
CONFIG_DD=y
CONFIG_CMP=y
# applet pruning (2026-11-19): dpkg/rpm, mail, printing, UBI/NAND, swap, VT console, runit (init is enough), vi
# CONFIG_DPKG is not set
# CONFIG_DPKG_DEB is not set
# CONFIG_RPM is not set
# CONFIG_RPM2CPIO is not set
# CONFIG_MAKEMIME is not set
# CONFIG_POPMAILDIR is not set
# CONFIG_REFORMIME is not set
# CONFIG_SENDMAIL is not set
# CONFIG_LPD is not set
# CONFIG_LPR is not set
# CONFIG_LPQ is not set
# CONFIG_UBIATTACH is not set
# CONFIG_UBIDETACH is not set
# CONFIG_UBIMKVOL is not set
# CONFIG_UBIRMVOL is not set
# CONFIG_UBIRSVOL is not set
# CONFIG_UBIUPDATEVOL is not set
# CONFIG_UBIRENAME is not set
# CONFIG_NANDWRITE is not set
# CONFIG_NANDDUMP is not set
# CONFIG_MKSWAP is not set
# CONFIG_SWAPON is not set
# CONFIG_SWAPOFF is not set
# CONFIG_CHVT is not set
# CONFIG_DEALLOCVT is not set
# CONFIG_DUMPKMAP is not set
# CONFIG_FGCONSOLE is not set
# CONFIG_KBD_MODE is not set
# CONFIG_LOADFONT is not set
# CONFIG_LOADKMAP is not set
# CONFIG_OPENVT is not set
# CONFIG_SETCONSOLE is not set
# CONFIG_SETFONT is not set
# CONFIG_SETKEYCODES is not set
# CONFIG_SETLOGCONS is not set
# CONFIG_SHOWKEY is not set
# CONFIG_CONSPY is not set
# CONFIG_CHPST is not set
# CONFIG_ENVDIR is not set
# CONFIG_ENVUIDGID is not set
# CONFIG_RUNSV is not set
# CONFIG_RUNSVDIR is not set
# CONFIG_SETUIDGID is not set
# CONFIG_SOFTLIMIT is not set
# CONFIG_SV is not set
# CONFIG_SVC is not set
# CONFIG_SVLOGD is not set
# CONFIG_SVOK is not set
# CONFIG_VI is not set
# SMALL_FLASH (model: OpenWrt Config-defaults.in, 2026-11-19): tools, network servers, archivers other than gzip/tar
# CONFIG_BC is not set
# CONFIG_BOOTCHARTD is not set
# CONFIG_POWERTOP is not set
# CONFIG_READPROFILE is not set
# CONFIG_SETARCH is not set
# CONFIG_LINUX32 is not set
# CONFIG_LINUX64 is not set
# CONFIG_RDEV is not set
# CONFIG_FREERAMDISK is not set
# CONFIG_RAIDAUTORUN is not set
# CONFIG_MAKEDEVS is not set
# CONFIG_MAN is not set
# CONFIG_ED is not set
# CONFIG_HEXEDIT is not set
# CONFIG_FSCK_MINIX is not set
# CONFIG_MKFS_MINIX is not set
# CONFIG_MKE2FS is not set
# CONFIG_MKFS_EXT2 is not set
# CONFIG_CAL is not set
# CONFIG_FTPD is not set
# CONFIG_TFTPD is not set
# CONFIG_DNSD is not set
# CONFIG_UDHCPD is not set
# CONFIG_DHCPRELAY is not set
# CONFIG_DUMPLEASES is not set
# CONFIG_FAKEIDENTD is not set
# CONFIG_INETD is not set
# CONFIG_NBDCLIENT is not set
# CONFIG_PSCAN is not set
# CONFIG_SLATTACH is not set
# CONFIG_SSL_SERVER is not set
# CONFIG_WHOIS is not set
# CONFIG_ZCIP is not set
# CONFIG_LZOP is not set
# CONFIG_LZMA is not set
# CONFIG_UNLZMA is not set
# CONFIG_LZCAT is not set
# CONFIG_XZ is not set
# CONFIG_UNXZ is not set
# CONFIG_XZCAT is not set
# CONFIG_BZIP2 is not set
# CONFIG_BUNZIP2 is not set
# CONFIG_BZCAT is not set
# CONFIG_CPIO is not set
# CONFIG_UNZIP is not set
# rarely needed + httpd + sha3sum (2026-11-19)
# CONFIG_FDFORMAT is not set
# CONFIG_FDFLUSH is not set
# CONFIG_MT is not set
# CONFIG_RX is not set
# CONFIG_BEEP is not set
# CONFIG_ASCII is not set
# CONFIG_MIM is not set
# CONFIG_SCRIPT is not set
# CONFIG_SCRIPTREPLAY is not set
# CONFIG_TS is not set
# CONFIG_RESUME is not set
# CONFIG_BLKDISCARD is not set
# CONFIG_FSTRIM is not set
# CONFIG_FSFREEZE is not set
# CONFIG_HDPARM is not set
# CONFIG_IFENSLAVE is not set
# CONFIG_ETHER_WAKE is not set
# CONFIG_IPTUNNEL is not set
# CONFIG_TUNCTL is not set
# CONFIG_HTTPD is not set
# CONFIG_SHA3SUM is not set
# base (2026-11-19): ~134 applets remain (the list in docs/roadmap.md is not needed - check busybox.links)
# CONFIG_ACPID is not set
# CONFIG_ADD_SHELL is not set
# CONFIG_ADJTIMEX is not set
# CONFIG_ARP is not set
# CONFIG_ARPING is not set
# CONFIG_BASE32 is not set
# CONFIG_BASE64 is not set
# CONFIG_BLOCKDEV is not set
# CONFIG_BRCTL is not set
# CONFIG_CHAT is not set
# CONFIG_CHATTR is not set
# CONFIG_CHGRP is not set
# CONFIG_CHPASSWD is not set
# CONFIG_CHROOT is not set
# CONFIG_CHRT is not set
# CONFIG_CKSUM is not set
# CONFIG_COMM is not set
# CONFIG_CRC32 is not set
# CONFIG_CROND is not set
# CONFIG_CRONTAB is not set
# CONFIG_CRYPTPW is not set
# CONFIG_CTTYHACK is not set
# CONFIG_DIFF is not set
# CONFIG_DNSDOMAINNAME is not set
# CONFIG_DOS2UNIX is not set
# CONFIG_EGREP is not set
# CONFIG_EJECT is not set
# CONFIG_EXPAND is not set
# CONFIG_FACTOR is not set
# CONFIG_FALLOCATE is not set
# CONFIG_FATATTR is not set
# CONFIG_FBSPLASH is not set
# CONFIG_FGREP is not set
# CONFIG_FINDFS is not set
# CONFIG_FLOCK is not set
# CONFIG_FOLD is not set
# CONFIG_FSYNC is not set
# CONFIG_FTPGET is not set
# CONFIG_FTPPUT is not set
# CONFIG_FUSER is not set
# CONFIG_GETFATTR is not set
# CONFIG_GETOPT is not set
# CONFIG_GROUPS is not set
# CONFIG_HD is not set
# CONFIG_HOSTID is not set
# CONFIG_HUSH is not set
# CONFIG_IFDOWN is not set
# CONFIG_IFPLUGD is not set
# CONFIG_IFUP is not set
# CONFIG_INSTALL is not set
# CONFIG_IONICE is not set
# CONFIG_IOSTAT is not set
# CONFIG_IPADDR is not set
# CONFIG_IPCALC is not set
# CONFIG_IPCRM is not set
# CONFIG_IPCS is not set
# CONFIG_IPLINK is not set
# CONFIG_IPNEIGH is not set
# CONFIG_IPROUTE is not set
# CONFIG_IPRULE is not set
# CONFIG_KILLALL5 is not set
# CONFIG_LAST is not set
# CONFIG_LINK is not set
# CONFIG_LINUXRC is not set
# CONFIG_LOGNAME is not set
# CONFIG_LOSETUP is not set
# CONFIG_LSATTR is not set
# CONFIG_LSBLK is not set
# CONFIG_LSOF is not set
# CONFIG_LSPCI is not set
# CONFIG_LSSCSI is not set
# CONFIG_MESG is not set
# CONFIG_MKDOSFS is not set
# CONFIG_MKFIFO is not set
# CONFIG_MKPASSWD is not set
# CONFIG_MORE is not set
# CONFIG_MOUNTPOINT is not set
# CONFIG_MPSTAT is not set
# CONFIG_NAMEIF is not set
# CONFIG_NL is not set
# CONFIG_NMETER is not set
# CONFIG_NOHUP is not set
# CONFIG_NOLOGIN is not set
# CONFIG_NPROC is not set
# CONFIG_NSENTER is not set
# CONFIG_OD is not set
# CONFIG_PARTPROBE is not set
# CONFIG_PASTE is not set
# CONFIG_PATCH is not set
# CONFIG_PGREP is not set
# CONFIG_PING6 is not set
# CONFIG_PIPE_PROGRESS is not set
# CONFIG_PIVOT_ROOT is not set
# CONFIG_PKILL is not set
# CONFIG_PMAP is not set
# CONFIG_PRINTENV is not set
# CONFIG_PSTREE is not set
# CONFIG_PWDX is not set
# CONFIG_RDATE is not set
# CONFIG_READAHEAD is not set
# CONFIG_REALPATH is not set
# CONFIG_REMOVE_SHELL is not set
# CONFIG_RENICE is not set
# CONFIG_RESIZE is not set
# CONFIG_REV is not set
# CONFIG_RTCWAKE is not set
# CONFIG_RUN_INIT is not set
# CONFIG_RUN_PARTS is not set
# CONFIG_RUNLEVEL is not set
# CONFIG_SEEDRNG is not set
# CONFIG_SETFATTR is not set
# CONFIG_SETPRIV is not set
# CONFIG_SETSERIAL is not set
# CONFIG_SETSID is not set
# CONFIG_SHA1SUM is not set
# CONFIG_SHA384SUM is not set
# CONFIG_SHA512SUM is not set
# CONFIG_SHRED is not set
# CONFIG_SHUF is not set
# CONFIG_SMEMCAP is not set
# CONFIG_SPLIT is not set
# CONFIG_SSL_CLIENT is not set
# CONFIG_START_STOP_DAEMON is not set
# CONFIG_STAT is not set
# CONFIG_SULOGIN is not set
# CONFIG_SUM is not set
# CONFIG_SWITCH_ROOT is not set
# CONFIG_TAC is not set
# CONFIG_TASKSET is not set
# CONFIG_TC is not set
# CONFIG_TCPSVD is not set
# CONFIG_TFTP is not set
# CONFIG_TRACEROUTE is not set
# CONFIG_TRACEROUTE6 is not set
# CONFIG_TREE is not set
# CONFIG_TRUNCATE is not set
# CONFIG_TSORT is not set
# CONFIG_TTY is not set
# CONFIG_TTYSIZE is not set
# CONFIG_UDHCPC6 is not set
# CONFIG_UDPSVD is not set
# CONFIG_UEVENT is not set
# CONFIG_UNEXPAND is not set
# CONFIG_UNIX2DOS is not set
# CONFIG_UNLINK is not set
# CONFIG_USERS is not set
# CONFIG_UUDECODE is not set
# CONFIG_UUENCODE is not set
# CONFIG_UUIDGEN is not set
# CONFIG_VCONFIG is not set
# CONFIG_VLOCK is not set
# CONFIG_VMSTAT is not set
# CONFIG_VOLNAME is not set
# CONFIG_W is not set
# CONFIG_WALL is not set
# CONFIG_WATCH is not set
# CONFIG_WHO is not set
# CONFIG_XXD is not set
# CONFIG_YES is not set
# CONFIG_BB_ARCH is not set
# CONFIG_BB_SYSCTL is not set
# ip instead of ifconfig/route, no tunnels; no klogd (dmesg) and dc (2026-11-19)
# CONFIG_IFCONFIG is not set
# CONFIG_ROUTE is not set
# CONFIG_FEATURE_IP_TUNNEL is not set
# CONFIG_KLOGD is not set
# CONFIG_DC is not set
# fsck: only the wrapper for fsck.<type> that we do not have
# CONFIG_FSCK is not set
# LTO (2026-11-19): -1.5% size; archives via gcc-ar (scripts/20-userspace.sh). MIPS16 dropped: GCC 16.2 ICE
CONFIG_EXTRA_CFLAGS="-flto=auto"
CONFIG_EXTRA_LDFLAGS="-flto=auto"
# nommu: NOFORK applets inside the shell (4.5x faster), the shell finds applets itself without symlinks (2026-11-19)
CONFIG_FEATURE_PREFER_APPLETS=y
CONFIG_FEATURE_SH_STANDALONE=y
CONFIG_FEATURE_SH_NOFORK=y
# kernel modules (the kernel now has CONFIG_MODULES: /proc/modules): lsmod reads /proc/modules, insmod/rmmod via init_module/delete_module
CONFIG_LSMOD=y
CONFIG_INSMOD=y
CONFIG_RMMOD=y
CONFIG_MODPROBE=y
# CONFIG_FEATURE_MODPROBE_BLACKLIST is not set
# CONFIG_DEPMOD is not set
# CONFIG_MODINFO is not set
# IPv6 removed entirely (decision 2026-11-22): telnetd/nc/wget/ifconfig IPv4 only
# CONFIG_FEATURE_IPV6 is not set
# microcom: serial terminal, not needed on the box
# CONFIG_MICROCOM is not set
