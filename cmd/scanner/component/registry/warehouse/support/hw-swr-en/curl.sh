#!/bash/bin
# 跳板机登录
docker login -u tensorsec -p TensorSec@Passw0rd 172.21.2.229:31517
# 获取镜像列表
curl -XGET -u tensorsec:TensorSec@Passw0rd 172.21.2.229:31517/v2/_catalog
# 获取单个镜像的taglisg
curl -XGET -u tensorsec:TensorSec@Passw0rd 172.21.2.229:31517/v2/tensorsecurity/image-alltest/tags/list

# 获取manifests

curl -XGET -u {user}:{pass} -H "Accept: application/vnd.docker.distribution.manifest.v2+json" 172.21.2.229:31517/v2/manifests/{pro}/{tag}


curl -XGET -k  -u "devops":"Hrbr12@Tensor.*#)" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" https://harbor.tensorsecurity.com/v2/tensorsecurity/scan-report-exporter/manifests/testcn


curl -XGET -u {user}:{pass} -H "Accept: application/vnd.docker.distribution.manifest.v2+json" 172.21.2.229:31517/v2/manifests/{pro}/{tag}

curl -XGET -u {user}:{pass}  {url}/dockyard/v2/repositories?filter=center::self