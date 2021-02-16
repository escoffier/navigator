#!/bin/bash

set -x
set -e

cd ..

echo "Make sure you've installed prequisites described in README of https://github.com/galexrt/k8s-vagrant-multi-node. If not, CTRL+C, else Enter"
tree -L 1


echo "Make sure you have docker registry running under name 'registry'"
read dummyanswer

echo "Configuring docker registry address for postinstall.sh"
PORT=$(docker inspect --format='{{ (index (index .HostConfig.PortBindings "5000/tcp") 0).HostPort }}' registry)
EXTIP=$(ip -o -4 addr list enp3s0 | awk {'print $4'} | cut -d/ -f1)

echo "Will use docker registry $EXTIP:$PORT. If it's correct, ENTER, else, CTRL+C and modify script"
read dummyanswer

sed -i "s/192.168.1.203:5000/$EXTIP:$PORT/g" ./tensornavigator/deployments/dev-multi-node/postinstall.sh



cd k8s-vagrant-multi-node

echo "Patching config.disksize.size"
set +e
git apply ../tensornavigator/deployments/dev-multi-node/disksize.patch
set -e

echo "Installing vagrant-disksize plugin"
vagrant plugin install vagrant-disksize

echo "Cleaning previous VMs"
make clean

echo "Provisioning VMs"
NODE_COUNT=1 BOX_OS=centos8 DISK_COUNT=1 DISK_SIZE_GB=40 MASTER_MEMORY_SIZE_GB=4 NODE_MEMORY_SIZE_GB=4 USER_POST_INSTALL_SCRIPT_PATH=../tensornavigator/deployments/dev-multi-node/postinstall.sh make up

cd -



cd tensornavigator/deployments/helm

echo "Installing helm"
sudo snap install helm --channel=2.16/stable --classic

echo "Starting helm tiller"
helm init

echo "Adding helm repos"
helm repo add stable https://kubernetes-charts.storage.googleapis.com
helm repo add elastic https://helm.elastic.co
helm repo add bitnami https://charts.bitnami.com/bitnami

cd -



echo "Configuring cluster role for tiller"
# Configure cluster role (https://stackoverflow.com/a/55098760)
kubectl create serviceaccount --namespace kube-system tiller
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
kubectl patch deploy --namespace kube-system tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}'

echo "Adding storage provisioner"
kubectl create serviceaccount storage-provisioner
kubectl create clusterrolebinding storage-provisioner-role --clusterrole=cluster-admin --serviceaccount=default:storage-provisioner

helm template ./sig-storage-local-static-provisioner/helm/provisioner/ --values ./tensornavigator/deployments/dev-multi-node/values.yaml > provi.yaml
kubectl create -f ./provi.yaml

kubectl get pv
# After a while, output should be something like:
# NAME                CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS      CLAIM   STORAGECLASS    REASON   AGE
# local-pv-1a3cbf29   39Gi       RWO            Retain           Available           local-storage            40s
# local-pv-218adf71   39Gi       RWO            Retain           Available           local-storage            40s

echo "Remove taint from master"
kubectl taint nodes master node-role.kubernetes.io/master-
kubectl describe node master



echo "Environment ready!"
