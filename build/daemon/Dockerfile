FROM ubuntu:20.04

## 配置国内yum源

RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && apt-get update \
    && apt-get full-upgrade -y \
    && apt-get install supervisor libdevmapper-dev libgpgme-dev -y \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install libglib2.0-dev -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt upgrade -y libasn1-8-heimdal libgssapi3-heimdal libhcrypto4-heimdal libheimbase1-heimdal libheimntlm0-heimdal libhx509-5-heimdal libkrb5-26-heimdal libpython3.8-minimal libpython3.8-stdlib libroken18-heimdal libwind0-heimdal python3.8 python3.8-minimal

COPY bin/daemon /
COPY bin/ns-mnt /
COPY ./configs/daemon/supervisord.conf /etc/
COPY ./configs/daemon/*.o /
COPY ./configs/drift-prevention/inject /

CMD ["supervisord"]
