#!/bin/bash

RANDOM_UUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

template=`cat "daemonset.yaml" | sed "s/{{RANDOM_UUID}}/$RANDOM_UUID/g"`

echo "$template" | microk8s kubectl apply -n tensorsec-test -f -
