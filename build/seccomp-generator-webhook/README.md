## Build

```bash
docker build -t registry.t-appagile.com/tensorsecurity/baseimage-seccomp-generator-webhook:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./baseimage-dockerfile
```
