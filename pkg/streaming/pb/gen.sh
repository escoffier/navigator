#! /bin/bash

protoc  -I=./ --go-grpc_out=require_unimplemented_servers=false:. --go_out=. cluster.proto