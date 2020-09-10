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

```bash
# Add to ~/.bashrc:
alias mk8="microk8s kubectl "
alias mk8v="mk8 --namespace=vegeta "
```

```bash
# Get console IP
CONSOLEIP=$(mk8v describe service console | grep IP: | awk '{print $2;}')
SCANNERIP=$(mk8v describe service scanner | grep IP: | awk '{print $2;}')

# Login
JWT=$(curl -X POST --data '{"username": "admin", "password": "admin", "type": "account"}' -H "Content-Type: application/json" http://$CONSOLEIP:8889/api/v1/rest-auth/login -v 2>&1 | grep Set-Cookie | awk '{print $3;}')

```
Scan image:

```bash
curl -v -X POST -H "Cookie: $JWT" --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json" http://$CONSOLEIP:8889/api/v1/scanner/scan

# Or directly to Scanner, bypassing JWT auth, hehe
curl -v -X POST --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json"  http://$SCANNERIP:8888/api/v1/scan/one
```

Some oneliners:

```bash
mongo "mongodb://redstone:redstoneMongo123@10.152.183.243:27017/vegeta?authMechanism=SCRAM-SHA-1"
```

```bash
ETCDCTL_API=3 etcdctl --endpoints=10.152.183.14:2379 get / --prefix
ETCDCTL_API=3 etcdctl --endpoints=10.152.183.14:2379 get /agents/agentID/pods/scanner/heartbeat
```

# Glossary

* Agent, AgentID - this means Tenant. There is a use case where our client has multiple k8s clusters that share physical hosts. AgentID differentiates instances of 
our components between those k8s clusters.
