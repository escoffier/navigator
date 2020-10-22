#Prepare environment

##Prepare kubernetes environment

```bash
sudo minikube delete

sudo sysctl fs.protected_regular=0
sudo minikube --v=4 --alsologtostderr --cpus 2 --memory 4096 start --driver=none --extra-config=apiserver.authorization-mode=Node,RBAC --container-runtime=docker
```

##Prepare host environment (remove leftovers from previous run)
```bash
sudo rm -rf /tmp/syscall.sock 
```

##Build tensordig

Build tensordig:

```bash
cd ..
go build .  
```

##Prepare docker registry

```bash
sudo kubectl apply -f helpers/kube-registry.yaml
```

In another terminal
```bash
sudo kubectl port-forward --namespace kube-system $(sudo kubectl get po -n kube-system | grep kube-registry-v0 | \awk '{print $1;}') 5001:5000
```

##Prepare and push dockers
```bash
( cd tensordig-client ; ./build.sh )
( cd elastalertdocker ; ./build.sh )
```

##Activate helm
```bash
sudo bin/helm-init-namespace.sh $(sudo kubectl config current-context) monitor 3.2.4
sudo helm repo add elastic https://helm.elastic.co
```

##Install daemonset

```bash
sudo helm dep up ./tensorsmon
sudo helm install tensorsmon ./tensorsmon
```

##Run tensordig

```bash
cd ..
sudo nice ./tensordig --config config/example.yaml
```

##Install some additional pods to check syscalls

```bash
sudo kubectl apply -f helpers/busybox-pod.yml
```

##Verify data
```bash
kubectl port-forward $(kubectl get po | grep elasticsearch-master | \awk '{print $1;}') 9200:9200
http://localhost:9200/_cat/indices/
http://localhost:9200/filebeat-*/_search
curl -X GET "localhost:9200/filebeat-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": { 
    "bool": { 
      "must": [
        { "match": { "open__filename":   "/etc/hosts"        }}
      ]
    }
  }
}
'
sudo kubectl port-forward $(sudo kubectl get po | grep elastalert | \awk '{print $1;}') 3030:3030
```

##Apply secccomp generator
```bash
cd seccomp-gen
./build.sh
cd ..
sudo kubectl apply -f seccomp-gen-serviceaccount.yaml
sudo kubectl apply -f seccomp-gen-job.yaml
```

#Known problems and issues
* Right now code is to demonstrate this working. Only gathering 5 process syscalls
* There seems to be a problem with closing unix socket between osquery and osquery-client, which then makes osquery-client restart. This needs further investigation.
