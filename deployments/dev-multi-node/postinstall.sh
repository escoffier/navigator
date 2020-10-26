#!/bin/bash

set -x
set -e

echo "Starting post install script"


echo "Mounting disks for PVs"

yes | sudo mkfs.ext4 -L sdb /dev/sdb
DISK_UUID=$(sudo blkid -s UUID -o value /dev/sdb)
echo $DISK_UUID
sudo mkdir -p /mnt/$DISK_UUID
sudo mount -t ext4 /dev/sdb /mnt/$DISK_UUID
echo UUID=`sudo blkid -s UUID -o value /dev/sdb` /mnt/$DISK_UUID ext4 defaults 0 2 | sudo tee -a /etc/fstab

for i in $(seq 1 10); do
  sudo mkdir -p /mnt/${DISK_UUID}/vol${i} /mnt/disks/${DISK_UUID}_vol${i}
  sudo mount --bind /mnt/${DISK_UUID}/vol${i} /mnt/disks/${DISK_UUID}_vol${i}
done
for i in $(seq 1 10); do
  echo /mnt/${DISK_UUID}/vol${i} /mnt/disks/${DISK_UUID}_vol${i} none bind 0 0 | sudo tee -a /etc/fstab
done


echo "Installing jq"
yes | sudo yum install jq


echo "Configuring insecure registry"
echo $(cat /etc/docker/daemon.json | jq ". + {\"insecure-registries\": [\"192.168.1.203:5000\"]}") > /etc/docker/daemon.json
sudo systemctl restart docker


# Only on master, so disable -e for now
set +e

echo "Enabling DefaultStorageClass"
sed -i 's/NodeRestriction/NodeRestriction,DefaultStorageClass/g' /etc/kubernetes/manifests/kube-apiserver.yaml
sudo systemctl restart kubelet.service

set -e


echo "Installing kernel headers"
yes | sudo yum install kernel-headers kernel-devel

