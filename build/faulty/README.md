## Build

```bash
docker build -t registry.t-appagile.com/tensorsecurity/baseimage-faulty:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./baseimage-dockerfile
```
