## Build

```bash
docker build -t registry.t-appagile.com/tensorsecurity/baseimage-tensordig:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./baseimage-dockerfile
```
