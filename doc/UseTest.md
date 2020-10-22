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
k8 port-forward -n tensorsec service/tensorsec-console 8889:8889 &
```

---

# Manual testing

## APIs

Obtain JWT token by logging into dashboard and inspecting subsequent HTTP request cookie header. 

Login:

 ```bash
# If multinode
k8 port-forward -n tensorsec service/tensorsec-console 8889:8889 &
k8 port-forward -n tensorsec service/tensorsec-scanner 8888:8888 &
CONSOLEADDR=127.0.0.1:8889
SCANNERADDR=127.0.0.1:8888

# if remote system
# CONSOLEADDR=console.tensorsecurity.cn:80

# If singlenode using microk8s
# CONSOLEIP=$(k8v describe service console | grep IP: | awk '{print $2;}')
# SCANNERIP=$(k8v describe service scanner | grep IP: | awk '{print $2;}')

# Login
JWT=$(curl -X POST --data '{"username": "admin", "password": "admin", "type": "account"}' -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/auth/login  | jq -r '.data.item.token')
```

Scan image:

```bash
# Old scan API
curl -v -X POST -H "Authorization: Bearer $JWT" --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/scan

# Get task details
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/task/5f7df28d0403ef8cdd1873f1

# Or directly to Scanner, bypassing JWT auth, hehe
# curl -v -X POST --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json"  http://$SCANNERIP:8888/api/v1/scan/one

# Invalidate scanner cache
curl -v -X POST -H "Content-Type: application/json"  http://$SCANNERADDR/api/v1/scan/forceInvalidateCache

# Retrigger harbor full scan
curl -v -X POST -H "Content-Type: application/json"  http://$SCANNERADDR/api/v1/scan/harborScanAll

# Obtain results ordered by severity from some timestamp
curl -v  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scanner/reportsBySeverity?from=1603222793" > out.json

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
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/scap/kube/5f8d86d0841e561ca4e81cc9
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

curl --request PUT 'http://127.0.0.1:8889/api/v1/scap/kube/5f75a5221b29c43e6838df66/cron' -H "Authorization: Bearer $JWT" --header 'Content-Type: application/json' --data-raw '{ "cronString": "*/5 * * * *" }'
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/5f75a5221b29c43e6838df66/cron"
```


## Database access

Some oneliners:

```bash
mongo "mongodb://redstone:redstoneMongo123@localhost:27017/vegeta?authMechanism=SCRAM-SHA-1" --quiet --eval 'db.scantasks.find().toArray()' > out.json
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
microk8s kubectl --namespace tensorsec get pods --all-namespaces -o name | grep "-bench"  | xargs microk8s kubectl --namespace tensorsec delete

# Delete all scap jobs (will remove pods as well)
kubectl --namespace tensorsec get job --all-namespaces   | grep "-bench" | awk '{print $2}' | xargs kubectl --namespace tensorsec delete job
```
