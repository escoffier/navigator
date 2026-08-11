FROM ubuntu:24.04

ARG MIRROR_SOURCE=mirrors.aliyun.com

## 配置国内 apt 源（24.04 使用 deb822 ubuntu.sources）

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
      sed -i "s|archive.ubuntu.com|${MIRROR_SOURCE}|g; s|security.ubuntu.com|${MIRROR_SOURCE}|g; s|ports.ubuntu.com|${MIRROR_SOURCE}|g" /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
      sed -i "s|archive.ubuntu.com/|${MIRROR_SOURCE}/|g; s|security.ubuntu.com/|${MIRROR_SOURCE}/|g; s|ports.ubuntu.com/|${MIRROR_SOURCE}/|g" /etc/apt/sources.list; \
    fi; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      iptables language-pack-zh-han* google-perftools binutils; \
    apt-get full-upgrade -y; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

ENV LANG=zh_CN.UTF-8
ENV LANGUAGE=zh_CN:zh
ENV LC_ALL=zh_CN.UTF-8
# ENV LD_PRELOAD=/lib/x86_64-linux-gnu/libtcmalloc.so.4
# ENV HEAPPROFILE=profile 
# ENV HEAP_PROFILE_TIME_INTERVAL=1000

COPY heavy_agent/net-rule /
# COPY ./configs/heavy-agent/libasan.so.8 /lib/x86_64-linux-gnu/
COPY ./configs/heavy-agent/run_agent.sh /
RUN chmod +x /run_agent.sh
# RUN echo '/tmp/core.%e.%p' | tee /proc/sys/kernel/core_pattern

# ENTRYPOINT [ "./net-rule" ] 
ENTRYPOINT [ "./run_agent.sh" ] 
