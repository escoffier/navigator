#! /bin/bash

#protoc  -I=./ --go-grpc_out=require_unimplemented_servers=false:. --go_out=. cluster.proto
#protoc  -I=./ --go-grpc_out=require_unimplemented_servers=false:. --go_out=. image_sec.proto
protoc  -I=./ --go-grpc_out=require_unimplemented_servers=false:. --go_out=. compliance.proto
