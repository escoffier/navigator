#! /bin/bash

rm -rf inject/tensor/dp.so

mkdir -p inject/tensor
# if [ -z "$1" ]; then
#     docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build .
# else
#     docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build \
#         --build-arg MIRROR="$1" .
# fi

docker build -f rhel/Dockerfile.rhel -t drift-prevention-rhel:build .

id=$(docker create drift-prevention-rhel:build)
docker cp $id:/src/dp.so inject/tensor/dp.so
docker rm -v $id
