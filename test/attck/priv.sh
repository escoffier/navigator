#Privilege Escalation
#1.rule: Launch Privileged Container
#done

#2.rule: Non sudo setuid
# not user.name=root 
touch /tmp/thisistest
chmod +s /tmp/thisistest
rm /tmp/thisistest
