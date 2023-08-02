FROM ubuntu:20.04

ARG MIRROR_SOURCE=mirrors.aliyun.com

## 配置国内yum源

RUN sed -i "s!archive.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
    supervisor libdevmapper-dev libgpgme-dev libglib2.0-dev iptables \
    language-pack-zh-han* \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=zh_CN.UTF-8
ENV LANGUAGE=zh_CN:zh
ENV LC_ALL=zh_CN.UTF-8

COPY bin/daemon /
COPY bin/ns-mnt /
COPY bin/net-rule /
COPY ./configs/daemon/supervisord.conf /etc/
COPY ./configs/daemon/*.o /
COPY ./configs/drift-prevention/inject /
COPY ./configs/daemon/cis /cis

## avira
ADD avira/savapi-sdk-linux64.tgz /usr/local
ADD ./configs/daemon/savapi.conf /etc/savapi/savapi.conf

## hm
ADD hm/hm-linux.tgz /usr/bin/

CMD ["supervisord"]
