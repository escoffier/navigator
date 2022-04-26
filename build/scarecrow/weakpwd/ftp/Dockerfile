FROM ubuntu:20.04

ARG MIRROR=mirrors.aliyun.com

RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list \
    && DEBIAN_FRONTEND=noninteractive apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --fix-missing vsftpd \
    && useradd -m ftpuser \
    && echo 'ftpuser:ftpuser123'|chpasswd \
    && echo ftpuser > /etc/vsftpd.chroot_list \
    && rm -rf /var/lib/apt/lists/

COPY vsftpd.conf /etc/vsftpd.conf

CMD ["/bin/bash", "-c", "service vsftpd start && sleep 99999"]
