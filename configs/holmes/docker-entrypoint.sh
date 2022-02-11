#!/usr/bin/env bash
#
# Copyright (C) 2020 The Falco Authors.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# todo(leogr): remove deprecation notice within a couple of releases
main=`uname -r | awk -F . '{print $1}'`
minor=`uname -r | awk -F . '{print $2}'`
echo "kernel version is :$main.$minor"

if [ "$main" -ge 4 -a "$minor" -ge 14 ] || [ "$main" -ge 5 ]
    then
        # export FALCO_BPF_PROBE=''
        # TODO: check ebpf reference: https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration
        if [ -v HOLMES_BPF_PROBE ]; then
            echo "ebpf module!"
        fi

    else
        if [ -v HOLMES_BPF_PROBE ]; then
            unset HOLMES_BPF_PROBE
        fi
        echo "kernel module!"
fi


if [[ ! -z "${SKIP_MODULE_LOAD}" ]]; then
    echo "* SKIP_MODULE_LOAD is deprecated and will be removed soon, use SKIP_DRIVER_LOADER instead"
fi

# Set the SKIP_DRIVER_LOADER variable to skip loading the driver

if [[ -z "${SKIP_DRIVER_LOADER}" ]] && [[ -z "${SKIP_MODULE_LOAD}" ]]; then
    echo "* Setting up /usr/src links from host"

    for i in "$HOST_ROOT/usr/src"/*
    do
        base=$(basename "$i")
        ln -s "$i" "/usr/src/$base"
    done

    /usr/bin/holmes-driver-loader
fi

exec /holmes-scheduler --output /tmp/latest_rules.yaml --holmes-args "$*"
