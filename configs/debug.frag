# Development kernel: verbose boot, panic on oops and reboot after 5 s (use with patches/optional/dev-watchdog-feeder.patch)
# ('nowait': the 4Kc 'wait' instruction does not always wake on the timer interrupt)
CONFIG_CMDLINE="console=ttyS0,115200e8 ignore_loglevel nowait oops=panic panic=5 dev_watchdog.timeout=5"
CONFIG_PRINTK_TIME=y
CONFIG_KALLSYMS=y
