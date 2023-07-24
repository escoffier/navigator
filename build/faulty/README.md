## Build

```bash
docker build -t harbor.tensorsecurity.com/tensorsecurity/baseimage-faulty:latest \
    --build-arg MIRROR=mirrors.aliyun.com -f ./baseimage-dockerfile .
```
