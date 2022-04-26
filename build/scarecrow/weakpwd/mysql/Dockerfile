FROM ubuntu:18.04

ARG MIRROR=mirrors.aliyun.com

ADD run.sh /

RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list \
    && DEBIAN_FRONTEND=noninteractive apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --fix-missing mysql-server \
    && chmod +x /run.sh \
    && rm -rf /var/lib/apt/lists/

CMD ["/run.sh"]