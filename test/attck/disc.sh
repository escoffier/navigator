#Discovery
#1.rule: Read Shell Configuration File
#never true
cat /root/.bashrc

#2.rule: Read ssh information
#never true
cat /root/.ssh/authorized_keys

#3.rule: Read sensitive file untrusted
cat /etc/shadow

#4.rule: Contact K8S API Server From Container
#need env

#5.rule: Lauch Suspicious Network Tool in Container
dig
#tcpdump &
nc
ncat
nmap
#tshark &
#ngrep &

#6.rule: Launch Suspicious Network Tool on Host
#need host env
