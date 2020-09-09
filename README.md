# Vegeta

## Prepare environment

Instructions for Ubuntu 1804:

1. Install microk8s (I have v1.3.4), then to use as non-sudo: 

```bash
sudo gpasswd -a $USER microk8s
newgrp microk8s
sudo chown -f -R $USER ~/.kube
```

2. Prepare microk8s environment:

```bash
microk8s enable dashboard dns registry storage helm
microk8s helm init
microk8s helm repo add elastic https://helm.elastic.co
```

3. Install docker (I have v19.03.11), then to use as non-sudo:

```bash
sudo setfacl -m user:$USER:rw /var/run/docker.sock
sudo groupadd docker
sudo gpasswd -a $USER docker
```

4. Install golang (I have v1.15.1)
5. Install build tools

```bash
sudo apt-get install make gcc npm python python-setuptools
go get -u github.com/swaggo/swag/cmd/swag
go get -u golang.org/x/lint/golint
```

6. Run npm install for the first time:

```bash
cd cmd/console/install; npm install; cd -;
```

## Build

Build bins and npm and put under dist/. Then creates docker images.

```bash
make all
```

*Note: all docker image tags are prefixed with REPOPREFIX, see Makefile. By default, this variable points to local repo managed by microk8s.*

## Push

Pushes all images to docker registry.

```bash
make pushimages
```

*Note: uses docker image tag prefix REPOPREFIX, see Makefile.*

## Deploy

Simplified version for development:

```bash
make redeploy
```

*Note: more deployment options described in deployments/helm/README.md.*
*Note2: Helm charts contain references to old gitlab docker repos. Need to be cleaned up.*

After a while, ensure all pods are RUNNING:

```bash
microk8s helm get pod --namespace=vegeta
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
microk8s kubectl describe service console --namespace=vegeta
```
```bash
# Example
IP:                10.152.183.236
Port:              console  8889/TCP
```

Go to this IP and port in browser. Default username/password is admin/admin.




# Manual testing

Obtain JWT token by logging into dashboard and inspecting subsequent HTTP request cookie header. 

Scan image:


```bash
curl -X POST -H "Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1OTk2NDI2NTIsInVzZXJuYW1lIjoiYWRtaW4ifQ.h_9FBr7SXbYxdmBjCScnlcjNnQG4oE_fdsif7A4lGeM" --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json" http://10.152.183.238:8889/api/v1/scanner/scan -v
```