#!/bin/sh
set -e

processid=$1
echo "processid $processid"

HOSTPATH=/host/tmp/tensor/
CONTPATH=/tmp
HOST_ETC_PRELOAD=/host/tmp/tensor/ld.so.preload
CONTAINER_ETC_PRELOAD=/etc/ld.so.preload

cp -r /tensor /tmp && sync

REALPATH=$(readlink --canonicalize $HOSTPATH)
FILESYS=$(df -P $REALPATH | tail -n 1 | awk '{print $6}')

echo "realpath $REALPATH,filesys $FILESYS"

while read DEV MOUNT JUNK
do [ $MOUNT = $FILESYS ] && break
done </proc/mounts
[ $MOUNT = $FILESYS ] # Sanity check!

echo "mount $MOUNT dev $DEV"

while read A B C SUBROOT MOUNT JUNK
do [ $MOUNT = $FILESYS ] && break
done < /proc/self/mountinfo
[ $MOUNT = $FILESYS ] # Moar sanity check!

SUBPATH=$(echo $REALPATH | sed s,^$FILESYS,,)
DEVDEC=$(printf "%d %d" $(stat --format "0x%t 0x%T" $DEV))

echo "REALPATH=$REALPATH FILESYS=$FILESYS SUBROOT=$SUBROOT SUBPATH=$SUBPATH DEVDEC=$DEVDEC DEV=$DEV"

docker_enter()
{
    # echo $@
    nsenter --target $processid --mount --uts --ipc --net -- \
        "$@"
}

inject_container(){

    docker_enter sh -c \
            "[ -b $DEV ] || mknod --mode 0660 $DEV b $DEVDEC"
    docker_enter mkdir /tmpmnt
    docker_enter mount $DEV /tmpmnt
    docker_enter mkdir -p $CONTPATH
    docker_enter mount -o bind /tmpmnt$SUBROOT$SUBPATH $CONTPATH
    docker_enter touch $CONTAINER_ETC_PRELOAD && sync
    docker_enter mount -o bind,ro /tmpmnt$SUBROOT$SUBPATH/ld.so.preload $CONTAINER_ETC_PRELOAD
    docker_enter umount /tmpmnt
    docker_enter rmdir /tmpmnt
}

inject_container
