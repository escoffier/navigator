rm -rf ld-preload

mkdir -p ld-preload/ubuntu
if [ -z "$1" ]; then
    docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build .
else
    docker build -f ubuntu/Dockerfile.ubuntu -t drift-prevention-ubuntu:build \
        --build-arg MIRROR="$1" .
fi

id=$(docker create drift-prevention-ubuntu:build)
docker cp $id:/src/dp.so ld-preload/ubuntu/dp.so
docker rm -v $id

mkdir -p ld-preload/alpine
if [ -z "$1" ]; then
    docker build -f alpine/Dockerfile.alpine -t drift-prevention-alpine:build .
else
    docker build -f alpine/Dockerfile.alpine -t drift-prevention-alpine:build \
        --build-arg MIRROR="$1" .
fi

id=$(docker create drift-prevention-alpine:build)
docker cp $id:/src/dp.so ld-preload/alpine/dp.so
docker rm -v $id

mkdir -p ld-preload/centos
if [ -z "$1" ]; then
    docker build -f centos/Dockerfile.centos -t drift-prevention-centos:build .
else
    docker build -f centos/Dockerfile.centos -t drift-prevention-centos:build \
        --build-arg MIRROR="$1" .
fi

id=$(docker create drift-prevention-centos:build)
docker cp $id:/src/dp.so ld-preload/centos/dp.so
docker rm -v $id
