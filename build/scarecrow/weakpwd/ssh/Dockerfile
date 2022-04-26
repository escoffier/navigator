FROM ubuntu:18.04

ARG MIRROR=mirrors.aliyun.com

RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list \
    && DEBIAN_FRONTEND=noninteractive apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --fix-missing openssh-server \
    && echo 'root:test123456'|chpasswd \
    && echo "PermitRootLogin yes" >> /etc/ssh/sshd_config \
    && mkdir /var/run/sshd \
    && rm -rf /var/lib/apt/lists/

CMD ["/usr/sbin/sshd","-D"]