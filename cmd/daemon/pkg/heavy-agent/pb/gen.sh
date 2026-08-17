#! /bin/bash

protoc -I=. --go_out=. --go-grpc_out=require_unimplemented_servers=false:. \
    net_policy_common.proto net_policy_control.proto net_policy_events.proto
