#!/bin/zsh

# 查看启动成功与否
kubectl config use-context sit
podNameRun=$(kubectl get pod -n tensorsec | grep -v tensorsec-scanner-dockerregistry | grep -v tensorsec-scanner-scan-report | grep tensorsec-scanner | sed -n 1p | awk '{print $3}')
podName=$(kubectl get pod -n tensorsec | grep -v tensorsec-scanner-dockerregistry | grep -v tensorsec-scanner-scan-report | grep tensorsec-scanner | sed -n 1p | awk '{print $1}')

while [ "$podNameRun" != "Running" ]; do
  sleep 1s
  podNameRun=$(kubectl get pod -n tensorsec | grep -v tensorsec-scanner-dockerregistry | grep -v tensorsec-scanner-scan-report | grep tensorsec-scanner | sed -n 1p | awk '{print $3}')
  podName=$(kubectl get pod -n tensorsec | grep -v tensorsec-scanner-dockerregistry | grep -v tensorsec-scanner-scan-report | grep tensorsec-scanner | sed -n 1p | awk '{print $1}')
done

echo "podName is $podName"
echo "podNameRun is $podNameRun"

if [ -n "$1" ]; then
  kubectl logs -f --tail 10 "$podName" -n tensorsec | grep "$1"
else
  kubectl logs -f --tail 10 "$podName" -n tensorsec
fi

