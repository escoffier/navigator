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

### Login:

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

### Scanning

Scan image:

```bash
# Old scan API
curl -v -X POST -H "Authorization: Bearer $JWT" --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/scan

# Get task details
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/task/5f7df28d0403ef8cdd1873f1

# Retrigger full scan in harbor
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/harbor/scanAllNow

# Redirect to harbor scan configuration screen
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" http://$CONSOLEADDR/api/v1/scanner/harbor/scanConfig



# Or directly to Scanner, bypassing JWT auth, hehe
# curl -v -X POST --data '{"image": "python", "rescan": false}' -H "Content-Type: application/json"  http://$SCANNERIP:8888/api/v1/scan/one

# Invalidate scanner cache
curl -v -X POST -H "Content-Type: application/json"  http://$SCANNERADDR/api/v1/scan/dev/forceInvalidateCache

# Retrigger harbor full scan
curl -v -X POST -H "Content-Type: application/json"  http://$SCANNERADDR/api/v1/scan/harbor/ScanAll

# Obtain results ordered by severity from some timestamp
# Note: RFC3339 timestamp helper, see https://www.unixtimestamp.com/ (CTRL+F "RFC 3339")
# Remember to replace + with %2B
curl -v  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scanner/reportsBySeverity?from=2020-10-21T00:00:00%2B01:00" > out.json
curl -v  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scanner/reportsBySeverity?from=2020-10-21T00:00:00%2B01:00&to=2020-10-22T00:00:00%2B01:00" > out.json
```

### Clusters


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

# Delete cluster
curl -v -X DELETE -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/config/cluster/5f99bd6640565eb2ac723254
```

### Compliance

```bash
# Kube-bench
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/scap/kube/5fa69022046adaa45b057c55
# Docker-bench
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/scap/docker/5fa69022046adaa45b057c55
# Host-bench
curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  http://$CONSOLEADDR/api/v1/scap/host/5fa69022046adaa45b057c55

# They return Check id 0e87b7ae-9711-4d5f-b2c2-17b18ca0ee94


# Get results using cluster ID and optional query parameters
# kube-bench
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/5fa69022046adaa45b057c55/reports?checkId=739e407b-ee8d-4cea-abd2-dd587a4e396a&nodeName=master&status=completed" > out.json

# docker-bench
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/docker/5fa69022046adaa45b057c55/reports?checkId=579737de-20b9-423f-92b2-90a53f26160b&nodeName=master&status=completed" > out.json

# host-bench
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/host/5fa03941d1044d02adfadfd4/reports?checkId=4f04bac6-2033-4577-b89a-68eb8f200828&status=completed" > out.json


curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/history" > out.json

curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/breakdown/f2200fc7-c08e-4a07-9ca7-6b8f4387b9a1" > out.json

curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/breakdown/cc7f68b4-d35f-4a97-8b0d-556751eb82a8/1.1.1/details" > out.json

curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/master/9e14db5e-e05a-479b-9cbf-f2d6f84fad1f/details" > out.json
```


/api/v1/scap/{checkType}/breakdown/{checkID}/{policyNumber}/details

Cronjobs:

```bash
curl --request PUT 'http://127.0.0.1:8889/api/v1/scap/kube/5f75a5221b29c43e6838df66/cron' -H "Authorization: Bearer $JWT" --header 'Content-Type: application/json' --data-raw '{ "cronString": "*/5 * * * *" }'
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/scap/kube/5f75a5221b29c43e6838df66/cron"
```

### Online vulnerabilities

```bash
# Get current list of online vulnerabilities:
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/onlineVulnerabilities/current" > out.json

# Get details of some pod without owner:
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/onlineVulnerabilities/details/NoOwner/ubuntuthing3" > single.json

# Get details of some online vulnerability, e.g. based on Replicaset:
k8 get replicaset
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/onlineVulnerabilities/details/ReplicaSet/tensorsec-scanner-6f658948d4"
```

### Runtime detection

```bash
curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/runtimeDetectionConfig/rules"

curl -v -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/runtimeDetectionConfig/rules/5f9aefa3ebe361737055d6c9/enable"

curl -v -X GET -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"  "http://$CONSOLEADDR/api/v1/alerts"
```

After enabling rule - you can simulate syscalls from a special pod, which has
to be started manually.

```bash
kubectl run tensorsec-faulty --image=registry.t-appagile.com/faulty:latest -i --tty --rm
# On dev environment:
kubectl apply -f deployments/test/faulty.yaml
```

## Database access

Some oneliners:

```bash
mongo "mongodb://redstone:redstoneMongo123@localhost:27017/vegeta?authMechanism=SCRAM-SHA-1" --quiet --eval 'db.scantasks.find().toArray()' > out.json
mongo "mongodb://redstone:redstoneMongo123@localhost:27017/vegeta?authMechanism=SCRAM-SHA-1" --quiet --eval 'db["docker-bench-records"].find().toArray()' > out2.json
```

```bash
ETCDCTL_API=3 etcdctl --endpoints=10.152.183.14:2379 get / --prefix
ETCDCTL_API=3 etcdctl --endpoints=10.152.183.14:2379 get /agents/agentID/pods/scanner/heartbeat
```


## Docker registry

```bash
curl -X GET http://localhost:5000/v2/_catalog
curl -X GET http://localhost:32000/v2/tensorsec-console/tags/list
```

## K8s

```bash
# Delete pods by pattern (dry run - uncomment last part of command to run for real)
microk8s kubectl --namespace tensorsec get pods --all-namespaces -o name | grep "-bench"  | xargs microk8s kubectl --namespace tensorsec delete

# Delete all scap jobs (will remove pods as well)
kubectl --namespace tensorsec get job --namespace tensorsec | grep "-bench" | awk '{print $2}' | xargs kubectl --namespace tensorsec delete job

# scale down some deployments by grep
k8 get deployment | grep harbor | awk '{print $1}' | xargs kubectl -n tensorsec scale --replicas 0 deployment {} 

```

## Mongo Topology errors

```bash
cat /proc/sys/net/ipv4/ip_forward
echo "1" > /proc/sys/net/ipv4/ip_forward
```

