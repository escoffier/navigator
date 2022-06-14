#!/bin/bash
# set -x
touch ./test
chmod +x ./test
for i in {1..100}
do
echo "round $i"
dd of=./test if=/dev/urandom count=1 ibs=1024 > /dev/null 2>&1
docker build . -t harbor.tensorsecurity.com/test/drift:$i > /dev/null
docker push harbor.tensorsecurity.com/test/drift:$i > /dev/null
docker rmi harbor.tensorsecurity.com/test/drift:$i > /dev/null
done
