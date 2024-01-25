FROM ubuntu:22.04

ARG MIRROR_SOURCE=mirrors.aliyun.com

## 配置国内yum源

RUN sed -i "s!archive.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
    iptables language-pack-zh-han* google-perftools binutils \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=zh_CN.UTF-8
ENV LANGUAGE=zh_CN:zh
ENV LC_ALL=zh_CN.UTF-8
# ENV LD_PRELOAD=/lib/x86_64-linux-gnu/libtcmalloc.so.4
# ENV HEAPPROFILE=profile 
# ENV HEAP_PROFILE_TIME_INTERVAL=1000

COPY heavy_agent/net-rule /
COPY run_agent.sh /
RUN chmod +x /run_agent.sh

ENTRYPOINT [ "./net-rule" ] 
# ENTRYPOINT [ "./run_agent.sh" ] 
