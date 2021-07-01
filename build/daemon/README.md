## Build

```bash
docker build -t registry.t-appagile.com/tensorsecurity/baseimage-daemon:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./baseimage-dockerfile
```
