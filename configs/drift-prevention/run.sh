#! /bin/bash

rm -rf inject/tensor/dp.so

mkdir -p inject/tensor
if [ -z "$1" ]; then
    docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build .
else
    docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build \
        --build-arg MIRROR="$1" .
fi

id=$(docker create drift-prevention-ubuntu:build)
docker cp $id:/src/dp.so inject/tensor/dp.so
docker rm -v $id
