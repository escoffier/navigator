FROM debian:13

ARG MIRROR_SOURCE=mirrors.aliyun.com

## 与 Jenkins 编译镜像 harbor.../golang:1.26.1（Debian 13）对齐，
## 避免 libdevmapper / libgpgme / glibc 版本不匹配。

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i "s|deb.debian.org|${MIRROR_SOURCE}|g; s|security.debian.org|${MIRROR_SOURCE}|g" /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
      sed -i "s|deb.debian.org|${MIRROR_SOURCE}|g; s|security.debian.org|${MIRROR_SOURCE}|g" /etc/apt/sources.list; \
    fi; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      supervisor libdevmapper1.02.1 libgpgme11t64 libglib2.0-0t64 iptables curl \
      locales; \
    sed -i 's/^# *zh_CN.UTF-8 UTF-8/zh_CN.UTF-8 UTF-8/' /etc/locale.gen; \
    locale-gen; \
    apt-get full-upgrade -y; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

ENV LANG=zh_CN.UTF-8
ENV LANGUAGE=zh_CN:zh
ENV LC_ALL=zh_CN.UTF-8

COPY bin/daemon /
COPY bin/ns-mnt /
COPY ./configs/daemon/supervisord.conf /etc/
COPY ./configs/daemon/*.o /
COPY ./configs/drift-prevention/inject /
COPY ./configs/daemon/cis /cis
COPY ./configs/daemon/memshell/Memory_Horse.yaml /etc/
# COPY ./configs/daemon/hmj_licence /hmj_licence


## avira
ADD avira/savapi-sdk-linux64.tgz /usr/local
ADD ./configs/daemon/savapi.conf /etc/savapi/savapi.conf

## hmj
# COPY hmj/hmj /usr/local/bin/hmj
# ## hm
# ADD hm/hm-linux.tgz /usr/bin/

# arthas
RUN mkdir /arthas
COPY  ./arthas/arthas*   /arthas/


CMD ["supervisord"]
