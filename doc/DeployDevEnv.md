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

5. Ensure kernel headers are installed:

```bash
# Centos
yum install kernel-headers
# Ubuntu/Debian
sudo apt install linux-headers-$(uname -r)
```

### k8s-vagrant-multi-node

This will install 2 node (1 master, 1 slave) cluster with Centos8, 4GB RAM and enough disk size each, install helm and setup storage.

```bash
# Follow the instructions on screen and be patient.
git clone https://github.com/galexrt/k8s-vagrant-multi-node ../k8s-vagrant-multi-node
git clone https://github.com/kubernetes-sigs/sig-storage-local-static-provisioner ../sig-storage-local-static-provisioner
./deployments/dev-multi-node/allinone.sh 
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
microk8s kubectl get pod --namespace=tensorsec
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
