printenv
cat /proc/self/cgroup
cat /etc/hosts
cat /proc/1/mountinfo
cat /proc/net/unix
cat /proc/self/mounts
cat /proc/self/status
cat /proc/1/cgroup
cat /etc/mtab
cat /etc/resolv.conf
ifconfig -a
capsh --print
cat /.dockerenv 
sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab
ln -s /etc/shadow test
