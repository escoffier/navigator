# Instructions on Helm-based Vegeta deployment
## kind (Kubernetes in Docker)
### Launch kind

1. Have docker and Go ready

2. Install the kind client, e.g. in OSX

`GO111MODULE="on" go get sigs.k8s.io/kind@v0.5.1`

3. Start kind container

`kind create cluster`

4. Setup kubectl

`export KUBECONFIG="$(kind get kubeconfig-path --name="kind")"`

5. Verify kind is working:

`kubectl cluster-info`

### Setup Helm

1. Create a service account "tiller"

`kubectl create serviceaccount --namespace kube-system tiller`

2. Bind the cluster-admin clusterrole to this servicecaccount

`kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount="kube-system:tiller"`

3. Deploy tiller

`helm init --history-max 200 --service-account tiller`

4. Verify Helm is working

`helm version`

You should get a response if it's working:

###
    Client: &version.Version{SemVer:"v2.14.3", GitCommit:"0e7f3b6637f7af8fcfddb3d2941fcc7cbebb0085", GitTreeState:"clean"}
    Server: &version.Version{SemVer:"v2.14.3", GitCommit:"0e7f3b6637f7af8fcfddb3d2941fcc7cbebb0085", GitTreeState:"clean"}

### Deploy Vegeta

`helm repo add elastic https://helm.elastic.co`

`helm repo add dgraph https://charts.dgraph.io`

`helm dep up`

`helm install ./ --namespace tensorsec --name tensorsec`

### Shutdown

`kind delete cluster`

-----

## Minishift
### Launch Minishift

1. Have VirtualBox ready

2. Install the minishift client, e.g. in OSX

`brew cask install minishift`

3. Start minishift VM:

`minishift start --vm-driver virtualbox --memory 8192`

4. Setup oc

`eval $(minishift oc-env)`

5. Verify Minishift is working:

`oc cluster-info`

### Setup Helm

1. Login as system:admin

`oc login -u system:admin`

2. Add scc/privileged to system:authenticated

`oc adm policy add-scc-to-group privileged system:authenticated`

3. Deploy Helm tiller

`oc apply -f tiller_openshift.yaml`

`oc policy add-role-to-user edit "system:serviceaccount:kube-system:tiller"`

4. Verify Helm is working

`helm version`

You should get a response if it's working:

###
    Client: &version.Version{SemVer:"v2.14.3", GitCommit:"0e7f3b6637f7af8fcfddb3d2941fcc7cbebb0085", GitTreeState:"clean"}
    Server: &version.Version{SemVer:"v2.14.3", GitCommit:"0e7f3b6637f7af8fcfddb3d2941fcc7cbebb0085", GitTreeState:"clean"}

### Deploy Vegeta

`oc new-project vegeta`

`helm repo add elastic https://helm.elastic.co`

`helm dep up`

`helm install ./ --namespace vegeta --name vegeta`

Port forwarding if needed:

`oc port-forward service/vegeta-kibana 5601`

`oc port-forward service/vegeta-mongo-express 8081`

`oc port-forward service/etcd-cluster-client 2379`

### Shutdown

`minishift delete`

-----

And then run elasticalert-create-index and use `elasticsearch-master` for the ES host

`kubectl --namespace vegeta exec -ti <vegeta-alerter-podname> elasticalert-create-index`
