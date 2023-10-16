#!/bin/bash

cd /home/liuqiang/tensornavigator || exit

#如果文件夹不存在，创建文件夹
if [ ! -d "/home/liuqiang/tensornavigator/dist" ]; then
  mkdir dist
fi

rm -f /home/liuqiang/tensornavigator/dist/scanner

# 加入scanner文件
cp /home/liuqiang/tensornavigator/cmd/scanner/scanner /home/liuqiang/tensornavigator/dist/scanner

chmod +x /home/liuqiang/tensornavigator/dist/scanner

ls -lh /home/liuqiang/tensornavigator/dist | grep scanner

cd /home/liuqiang/tensornavigator || exit

docker build -t harbor.tensorsecurity.com/tensorsecurity/scanner:latest \
  --build-arg REPO=harbor.tensorsecurity.com/tensorsecurity -f /home/liuqiang/tensornavigator/build/scanner/Dockerfile .

docker push harbor.tensorsecurity.com/tensorsecurity/scanner:latest

sleep 1

kubectl -n tensorsec delete pod -l app.kubernetes.io/component=scanner

# 查看启动成功与否
podNameRun=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $3}')
podName=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $1}')

echo "podName is $podName"
echo "podNameRun is $podNameRun"

while [ "$podNameRun" != "Running" ]; do
  sleep 1s
  podNameRun=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $3}')
  podName=$(kubectl get pod -n tensorsec | grep prod-scanner | sed -n 1p | awk '{print $1}')

  echo "podName is $podName"
  echo "podNameRun is $podNameRun"
done
echo "scanner re build: new pod name is :${podName}"

kubectl logs -f --tail 10 "$podName" -n tensorsec
