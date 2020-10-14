# Vegeta

Before you do anything, make sure that submodules are present:

```bash
git submodule init
git submodule update
```

## Prepare environment

Instructions for Ubuntu 2004.

There are many ways to prepare a kubernetes cluster for development. More deployment options described in deployments/helm/README.md.

I recommend usnig one of the following, since I (Michał) use them and may be able to answer questions in case there are problems:

1. local, 1 node deployment using microk8s
2. multinode, 2 node deployment using vagrant, behind NAT, using https://github.com/galexrt/k8s-vagrant-multi-node

*Note: I tried microk8s multinode feature but it's new and I had problems configuring networking, so I gave up.*

### Microk8s

1. Install microk8s (I have v1.3.4), then to use as non-sudo: 

```bash
sudo gpasswd -a $USER microk8s
newgrp microk8s
sudo chown -f -R $USER ~/.kube
```

2. Install kubectl, then configure it to use microk8s cluster.

```bash
mk8 config view --raw > ~/.kube/microk8s-config
```

Note: This is needed, because SCAP jobs make assumptions about mounting kubectl inside the container.

3. Prepare microk8s environment:

```bash
microk8s enable dashboard dns registry storage
```

4. Install docker (I have v19.03.11), then to use as non-sudo:

```bash
sudo setfacl -m user:$USER:rw /var/run/docker.sock
sudo groupadd docker
sudo gpasswd -a $USER docker
```

### k8s-vagrant-multi-node

1. Clone https://github.com/galexrt/k8s-vagrant-multi-node and install prerequisites (I use provider 'Virtualbox')

2. Deploy 2 node k8s centos8 cluster (1 worker, 1 master)

```bash
# Use: 
NODE_COUNT=1 BOX_OS=centos8 DISK_COUNT=1 DISK_SIZE_GB=40 MASTER_MEMORY_SIZE_GB=4 NODE_MEMORY_SIZE_GB=4 make up -j 2
```

3. Our nodes have 40GB disk each, but they're not mounted. So let's mount them. Also, we must configure docker insecure registry. Run the following commands on every node.

```bash
# To ssh to a node use 
make ssh-master
# or
# make ssh-node-1
```

On each node:

```bash
# Mount disks and prepare for discovery (according to https://github.com/kubernetes-sigs/sig-storage-local-static-provisioner/blob/master/docs/operations.md#sharing-a-disk-filesystem-by-multiple-filesystem-pvs):

############
# Copy paste the following commands as one and run
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
# Note: make sure that DISK_UUIDs weren't null in above commands, there is some race condition (hence the sleep).
# If it's null, use `df -h` and `umount` to unmount /dev/sdb. Also remove entries that were created in /etc/fstab.
############

# Configure insecure registry
# Modify the line
sudo vi /etc/docker/daemon.json
# Add "insecure-registries" : [ "192.168.1.203:32000" ], # <- address of your docker registry
sudo systemctl restart docker
exit
```

4. We must enable `DefaultStorageClass` plugin on k8s cluster to easily provision Persistent Volumes. Do this on master node:

```bash
make ssh-master
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
# modify the line 
# - --enable-admission-plugins=NodeRestriction,DefaultStorageClass
sudo systemctl restart kubelet.service
```

5. Add our cluster to kubeconfig:

```bash
# Make sure that previous ~/.kube/config doesn't exist - we don't want to merge them.
rm ~/.kube/config
make kubectl # This generates a new ~/.kube/config
mv ~/.kube/config  ~/.kube/multi-config

# Use this cluster:
export KUBECONFIG=/home/michal/.kube/multi-config
```

6. Install and config helm 2

```bash
sudo snap install helm --channel=2.16/stable --classic

cd deployments/helm
helm init
helm repo add stable https://kubernetes-charts.storage.googleapis.com
helm repo add elastic https://helm.elastic.co
cd -

# Configure cluster role (https://stackoverflow.com/a/55098760)
kubectl create serviceaccount --namespace kube-system tiller
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
kubectl patch deploy --namespace kube-system tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}'
```

7. To provision some persistent volumes - we will use https://github.com/kubernetes-sigs/sig-storage-local-static-provisioner:

```bash
kubectl create serviceaccount storage-provisioner
kubectl create clusterrolebinding storage-provisioner-role --clusterrole=cluster-admin --serviceaccount=default:storage-provisioner

git clone https://github.com/kubernetes-sigs/sig-storage-local-static-provisioner
cd !$:t

helm template ./helm/provisioner/ --values ../shiftleft-compliance/deployments/dev-multi-node/values.yaml > deployment/kubernetes/provi.yaml
kubectl create -f deployment/kubernetes/provi.yaml

kubectl get pv
# Should get output like:
# NAME                CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS      CLAIM   STORAGECLASS    REASON   AGE
# local-pv-1a3cbf29   39Gi       RWO            Retain           Available           local-storage            40s
# local-pv-218adf71   39Gi       RWO            Retain           Available           local-storage            40s
```

8. Untaint master

```bash
kubectl taint nodes master node-role.kubernetes.io/master-
```

9. You're good to go! However, if you notice that many of your pods get evicted, check node status.

```bash
# e.g.
kubectl describe node master
```

If you notice errors like "lack of ephemeral storage" you need to grow the root disk and partition on the node:

```bash
vagrant plugin install vagrant-disksize
vi ./k8s-vagrant-multi-node/vagrantfiles/Vagrantfile
# Add config.disksize.size = '20GB'

# On each node:
sudo cfdisk /dev/sda
# Resize -> Write -> Quit
sudo xfs_growfs /

# Verify with
df -h
```

## Build

### Prepare environment

1. Install golang (I have v1.15.1)
2. Install build tools

```bash
sudo apt-get install make gcc npm python python-setuptools
go get -u github.com/swaggo/swag/cmd/swag
go get -u golang.org/x/lint/golint
```

3. Run npm install for the first time:

```bash
cd cmd/console/install; npm install; cd -;
```

### Build

Build bins and npm and put under dist/. Then creates docker images.

```bash
make all
```

*Note: all docker image tags are prefixed with REPOPREFIX, see Makefile. By default, this variable points to local repo managed by microk8s.*

You can also be more specific with what you want to build. 
See dependencies of `all` recipe to see what components are available to build.

*Note: `Console` target has some dependencies, but they will only be built in
`all` target. This is to make it quicker to iterate on `Console`.*

## Push

Pushes all modified images to docker registry.

```bash
make pushimages
```

*Note: uses docker image tag prefix REPOPREFIX, see Makefile.*

Pushing to our docker registry:

```bash
# Add insecure registries entry to daemon.json:
# vi /var/snap/docker/current/config/daemon.json
#"insecure-registries": ["registry.t-appagile.com"],

# Login to docker registry
docker login registry.t-appagile.com/

# Retag images from local to remote registry
REPOPREFIX=registry.t-appagile.com/tensorsecurity REPOPREFIXOLD=localhost:32000 make retag

# Push retagged images
REPOPREFIX=registry.t-appagile.com/tensorsecurity make pushimages
```

## Deploy

1. You can switch between microk8s and multi node cluster by changing KUBECONFIG env variable:

```bash
export KUBECONFIG=/home/michal/.kube/multi-config
export KUBECONFIG=/home/michal/.kube/microk8s-config

# Check with:
#kubectl config view
```

2. Change `deployments/helm/values.yaml` to point to correct docker repo.
```bash
global:
  # If you only have microk8s cluster, this can stay as
  ourDockerRepo: 127.0.0.1:32000
  # Otherwise, supply address of docker registry
  # Note: notice, that microk8s already creates a docker registry for us
  # IP is the IP of my development PC/laptop. 
  #ourDockerRepo: 192.168.1.203:32000
```

3. After a while, ensure all pods are RUNNING:

```bash
microk8s kubectl get pod --namespace=vegeta
```

## Test


Run unit tests.

```bash
make TAGS=--tags=ci test
```

Run all tests (includes intergration tests, which (seem to) require running deployment).

```bash
make test
```

## Use

Check IP and port of console service:

```bash
kubectl describe service console --namespace=vegeta
```
```bash
# Example
IP:                10.152.183.236
Port:              console  8889/TCP
```

If you use single node setup, then go to this IP and port in browser. Default username/password is admin/admin.

Otherwise, you need to use port-forwarding and then in the browser connect to 127.0.0.1:8889 

```bash
k8 port-forward service/tensorsec-console 8889:8889 &
```

---

# Manual testing

## APIs

Obtain JWT token by logging into dashboard and inspecting subsequent HTTP request cookie header. 

Login:

 ```bash
# If multinode
k8 port-forward -n tensorsec service/tensorsec-console 8889:8889 &
CONSOLEADDR=127.0.0.1:8889

# if remote system
# CONSOLEADDR=console.tensorsecurity.cn:80

# If singlenode using microk8s
# CONSOLEIP=$(k8v describe service console | grep IP: | awk '{print $2;}')
# SCANNERIP=$(k8v describe service scanner | grep IP: | awk '{print $2;}')

# Login
JWT=$(curl -X POST --data '{"username": "admin", "password": "admin", "type": "account"}' -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/rest-auth/login  | jq -r '.data.item.token')
```

Scan image:

```bash
curl -v -X POST -H "Authorization: Bearer $JWT" --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/scan

curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/task/5f7df28d0403ef8cdd1873f1


# Or directly to Scanner, bypassing JWT auth, hehe
# curl -v -X POST --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json"  http://$SCANNERIP:8888/api/v1/scan/one

curl -v -X POST -H "Authorization: Bearer $JWT" --data '{"url": "asdf", "repository": "python"}' -H "Content-Type: application/json" http://$SCANNERIP:8888/api/v1/scan/one


```

Run scap job:

```bash
# if singlenode using microk8s
# For dev: microk8s kubectl config shows that k8s API is at 127.0.0.1. Replace it with externally routable IP of the host so that the pod can access it.
# Note: change 'enp3s0' depending on your system.
# ACTUALKUBEAPIADDRESS=$(ip -4 addr show enp3s0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
# CFG=$(microk8s kubectl config view --raw -o json | sed "s/127.0.0.1/$ACTUALKUBEAPIADDRESS/" | base64 | tr -d "\n ")

# if multinode
CFG=$(kubectl config view --raw -o json  | base64 | tr -d "\n ")
# if remote system
# CFG=$(ssh root@120.53.227.174 'kubectl config view --raw -o json  | base64 | tr -d "\n "')

# Create cluster
curl -v -X POST -H "Authorization: Bearer $JWT" --data "{\"name\": \"alitest\", \"config\": \"$CFG\"}" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/config/cluster
# Get cluster (object ID from previuos request)
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/config/cluster/5f7d9fcd9ccfdee7b1b4f936

# Kube-bench
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/scap/kube/5f7f4885a6ae36adb246b01a
# Docker-bench
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/scap/docker/5f75a5221b29c43e6838df66
# Host-bench
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/scap/host/5f75a5221b29c43e6838df66

# They return Check id 0e87b7ae-9711-4d5f-b2c2-17b18ca0ee94


# Get results using cluster ID and optional query parameters
# kube-bench
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/5f75a5221b29c43e6838df66/reports?checkId=ebb296ee-0ff7-4f70-9989-715a04796f04&nodeName=master&status=completed" > out.json

# docker-bench
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/docker/5f75a5221b29c43e6838df66/reports?checkId=7b659ec9-2966-4b3c-8afe-e8beda64d7a1&nodeName=master&status=completed" > out.json

# host-bench
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/host/5f75a5221b29c43e6838df66/reports?checkId=76b63e1f-06ac-4dd8-a78d-49d053933326&status=completed" > out.json



curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/history" > out.json




# Delete cluster
curl -v -X DELETE "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/config/cluster/5f7d9fcd9ccfdee7b1b4f936

```


```bash

curl --request PUT 'http://127.0.0.1:8889/api/v1/scap/kube/5f75a5221b29c43e6838df66/cron' -H "Authorization: Bearer $JWT" --header 'Content-Type: application/json' --data-raw '{ "newCronString": "*/5 * * * *" }'
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/5f75a5221b29c43e6838df66/cron"
```

## Database access

Some oneliners:

```bash
mongo "mongodb://redstone:redstoneMongo123@localhost:27017/vegeta?authMechanism=SCRAM-SHA-1" --quiet --eval 'db.scantasks.find()[0]' > out.json
mongo "mongodb://redstone:redstoneMongo123@localhost:27017/vegeta?authMechanism=SCRAM-SHA-1" --quiet --eval 'db["kube-bench-records"].find().toArray()' > out.json
```

```bash
ETCDCTL_API=3 etcdctl --endpoints=10.152.183.14:2379 get / --prefix
ETCDCTL_API=3 etcdctl --endpoints=10.152.183.14:2379 get /agents/agentID/pods/scanner/heartbeat
```


## Docker registry

```bash
curl -X GET http://localhost:5000/v2/_catalog
curl -X GET http://localhost:32000/v2/ubuntu/tags/list
```

## K8s


```bash
# Delete pods by pattern (dry run - uncomment last part of command to run for real)
microk8s kubectl --namespace vegeta get pods --all-namespaces -o name | grep "-bench"  | xargs microk8s kubectl --namespace vegeta delete

# Delete all scap jobs (will remove pods as well)
kubectl --namespace vegeta get job --all-namespaces   | grep "-bench" | awk '{print $2}' | xargs kubectl --namespace vegeta delete job
```

# Glossary

* Agent, AgentID - this means Tenant. There is a use case where our client has multiple k8s clusters that share physical hosts. AgentID differentiates instances of 
our components between those k8s clusters.
