FROM ubuntu:22.04
ARG MIRROR_SOURCE=mirrors.aliyun.com

RUN sed -i "s!archive.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && apt-get update -y \
    && apt-get full-upgrade -y \
    && apt-get install -y wget vim \
    && apt-get install -y libclamav-dev libgpgme-dev libdevmapper1.02.1 zip unzip musl \
    && apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common iptables \
    && curl -fsSL https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg | apt-key add - \
    && add-apt-repository "deb [arch=$(dpkg --print-architecture)] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu $(lsb_release -cs) stable" \
    && apt-get install -y  docker-ce-cli \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ADD hm/hm-linux.tgz /opt/webshell/hm

ADD avira/savapi-sdk-linux64.tgz /usr/local

#ADD clamav/clamav.tgz /var/lib/
RUN mkdir /etc/savapi && mkdir /var/log/savapi && mkdir /run/savapi

# RUN wget --http-user=admin --http-password='@&yZ3LetJ!FBA#PQ' http://file.tensorsecurity.com/savapi-sdk-linux64.tgz \
#     && tar -xf savapi-sdk-linux64.tgz \
#     && rm savapi-sdk-linux64.tgz && mv savapi-sdk-linux64 /usr/local/savapi-sdk-linux64 && mkdir /etc/savapi && mkdir /var/log/savapi

ADD configs/scanner/savapi.conf /etc/savapi/savapi.conf

ADD dist/scanner /
ADD configs/scanner /configs/scanner/
ADD configs/scanner/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

