#!/bin/bash

# block hm request
iptables -I OUTPUT -p tcp --dport 58000:58100 -j REJECT && echo "Iptable rules add SUCCESS!" || echo "Iptable rules add FAILED!"

/var/lib/tensor/node-image -c /var/lib/tensor/node-image.yaml "$@"
