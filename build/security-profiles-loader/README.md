## Build

```bash
docker build -t registry.t-appagile.com/tensorsecurity/baseimage-security-profiles-loader:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./baseimage-dockerfile .
```
