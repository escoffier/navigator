## Harbor integration


## Deploy Harbor in your dev environment

```bash
helm repo add harbor https://helm.goharbor.io

# Note: Harbor helm has strict deployment exposing requirements. Without meeting them, login screen doesn't work.
# For example: https://github.com/goharbor/harbor-helm/issues/75
# Therefore, we will use expose.type=nodePort. 

# !!!!!!!!!! This requires setting up port forwarding in Virtualbox! !!!!!!!
# IP is external IP of our laptop
helm install --name my-harbor \
   --set expose.type=nodePort \
   --set expose.tls.auto.commonName=someName \
   --set persistence.resourcePolicy=dontkeep \
   --set expose.ingress.hosts.core=192.168.1.203 \
   --set externalURL=https://192.168.1.203:30003 \
   --set trivy.enabled=false \
   --set notary.enabled=false \
   --set chartmuseum.enabled=false \
   --set clair.enabled=true\
   harbor/harbor

k8 describe svc harbor | grep NodePort
# Type:                     NodePort
# NodePort:                 http  30002/TCP
# NodePort:                 https  30003/TCP
# NodePort:                 notary  30004/TCP

# Go to Virtualbox -> Any of your VM node settings -> Network -> Advanced -> Port forwarding -> 30003 to 30003 in above case
# Then go to https://localhost:30003, ignore the certificate warning, and you should be able to login

# Default creds are: admin/Harbor12345

# To cleanup:
# helm delete --purge my-harbor
```

## Add Tensorsec plugin in Harbor

This is required so that Harbor uses Tensorsec Scanner as vulnerability scanner.

1. Go to Administration -> Interrogation services -> New scanner
2. Enter fields as follows

![Registration](./tensorsec_harbor.png)

notice, that Endpoint address is the address of Tensorsec Console, with /harbor sub-path.

If tensorsec-console is in a different namespace, but same kubernetes cluster as Harbor, use the following format:
`http://tensorsec-console.tensorsec.svc.cluster.local:8889/harbor`

3. Test Connection -> Save
4. Select Tensorsec -> Set as default

## Add Tensorsec user in Harbor

This is required so that Tensorsec Scanner can retrigger full scans of images in Harbor based on events, e.g.
critical update of Clair vulnerability database.

1. (required) Define external Harbor URL `harbor.harborURL` in `deployments/helm/subcharts/scanner/values.yaml`
2. (optional) Define `harbor.harborUsername` and `harbor.harborPassword` for Harbor API that Scanner will
   use in `deployments/helm/subcharts/scanner/values.yaml`
3. Go to Administration -> Users -> New user and create a new user (Note: for development,
   I recommend setting the same username and password as in `deployments/helm/subcharts/scanner/values.yaml` - then,
   you won't have to edit/redeploy the Scanner deployment).
4. (required) Select the user -> Set as admin

## Manual testing

How to add images from a local docker registry and scan them:

1. Go to Administration -> Registries -> New Endpoint and add your local docker registry (must set Provider to
   Docker Regitsry and must provide external IP address, e.g. http://192.168.1.203:5000)
2. Go to Replications -> New -> Pull based -> Provide source registry and MUST provide some arbitrary name for namespace.
3. Repliaction -> Select your rule -> Replicate
4. You can see logs by clicking on your replication rule -> click on "ID" number under executions table.
5. Go to Projects -> your namespace -> one of images -> select it -> scan.

How to manually trigger rescan of all images in Harbor via Scanner API:

```bash
k8 port-forward service/tensorsec-scanner 8888 &
curl -X POST localhost:8888/api/v1/scan/harborScanAll
# Expect 200 OK
```
