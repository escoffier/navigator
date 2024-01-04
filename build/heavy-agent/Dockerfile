FROM ubuntu:22.04

ARG MIRROR_SOURCE=mirrors.aliyun.com

## 配置国内yum源

RUN sed -i "s!archive.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
    iptables language-pack-zh-han* \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=zh_CN.UTF-8
ENV LANGUAGE=zh_CN:zh
ENV LC_ALL=zh_CN.UTF-8

COPY heavy_agent/net-rule /

ENTRYPOINT [ "./net-rule" ] 
