#Defense Evasion 
#1.rule: Clear Log Activities
mkdir /tmp/thisistest/
echo > /tmp/thisistest/syslog 

#2.rule: Delete Bash History
echo test >> /root/.bash_history 
shred /root/.bash_history 
rm /root/.bash_history 
