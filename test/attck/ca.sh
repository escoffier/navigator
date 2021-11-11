#Credential Access
#1.rule: Read sensitive file trusted after startup
#need env

#2.Search Private Keys or Passwords
cat authorized_keys |grep 'BEGIN PRIVATE'
