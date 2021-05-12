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
