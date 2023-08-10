#!/bin/bash

# clear
num=`iptables -S |grep 58000 | wc -l`
echo "iptables num:$num"
for i in  $(seq 1 $num)
do
  ret=`iptables -D OUTPUT -p tcp -m tcp --dport 58000:58100 -j REJECT`
  echo "delete ret:$ret"
done

/var/lib/tensor/node-image -c /var/lib/tensor/node-image.yaml "$@"
