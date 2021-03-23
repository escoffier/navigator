#! /bin/bash

main=`uname -r | awk -F . '{print $1}'`
minor=`uname -r | awk -F . '{print $2}'`

if [ "$main" -ge 4 -a "$minor" -ge 14 ] || [ "$main" -ge 5 ]
    then
	    echo "main version is :$main.$minor"
            # check ebpf
    else
    sed -i '/ebpf:/{n;s/enabled: true/enabled: false/;}' ../helm/values.yaml
fi
