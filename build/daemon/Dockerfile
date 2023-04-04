FROM ubuntu:20.04

## 配置国内yum源

RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install supervisor libdevmapper-dev libgpgme-dev -y libglib2.0-dev -y \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY bin/daemon /
COPY bin/ns-mnt /
COPY ./configs/daemon/supervisord.conf /etc/
COPY ./configs/daemon/*.o /
COPY ./configs/drift-prevention/inject /

## avira
ADD avira/savapi-sdk-linux64.tgz /usr/local
ADD ./configs/daemon/savapi.conf /etc/savapi/savapi.conf

CMD ["supervisord"]
