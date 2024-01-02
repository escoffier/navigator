#!/bin/zsh

# 查看启动成功与否
kubectl config use-context prod
podNameRun=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $3}')
podName=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $1}')

while [ "$podNameRun" != "Running" ]; do
  sleep 1s
  podNameRun=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $3}')
  podName=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $1}')
done

echo "podName is $podName"
echo "podNameRun is $podNameRun"

kubectl -n tensorsec exec  -it "$podName" -- /bin/bash
