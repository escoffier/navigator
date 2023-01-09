#!/bin/bash

iptables -I OUTPUT -p tcp --dport 58000:58100 -j REJECT && echo "Iptable rules add SUCCESS!" || echo "Iptable rules add FAILED!"
/scanner "$@"
