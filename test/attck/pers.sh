#Persistence
#1.rule: Modify Shell Configuration File 
#not proc.name in (shell_binaries)
#mv /root/.bash_history /root/.bash_history_old
#echo thisistest >> /root/.bash_history
#mv /root/.bash_history_old /root/.bash_history


#2.rule: Schedule Cron Jobs
echo  "* * * * * whoami > /root/test" >> /var/spool/cron/crontabs/root
echo  "* * * * * whoami > /root/test" >> /var/spool/cron/root
echo  "* * * * * whoami > /root/test" >> /etc/cron/

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
