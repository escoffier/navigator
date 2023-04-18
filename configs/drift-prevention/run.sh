#! /bin/bash

rm -rf inject/tensor/dp.so

mkdir -p inject/tensor
# if [ -z "$1" ]; then
#     docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build .
# else
#     docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build \
#         --build-arg MIRROR="$1" .
# fi
if [ "$(uname -m)" == "aarch64" ]; then
    echo "Building for ARM64"
    docker build -f arm64/Dockerfile.ubuntu -t drift-prevention:build .
else
    echo "Building for x86_64"
    docker build -f rhel/Dockerfile.rhel -t drift-prevention:build .
fi

id=$(docker create drift-prevention:build)
docker cp $id:/src/dp.so inject/tensor/dp.so
docker rm -v $id
