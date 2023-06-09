FROM ubuntu:22.04
WORKDIR /var/lib/tensor
RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && apt-get update -y \
    && apt-get full-upgrade -y \
    && apt-get install -y libclamav-dev iptables language-pack-zh-han* \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

#ENV PATH="${PATH}:/var/lib/tensor"

# 病毒扫描支持中文文件名
ENV LANG=zh_CN.UTF-8
ENV LANGUAGE=zh_CN:zh
ENV LC_ALL=zh_CN.UTF-8

COPY dist/node-image /var/lib/tensor/
COPY configs/node-image/irene /var/lib/tensor/
COPY configs/node-image/policy-node-image /var/lib/tensor/policy/
COPY configs/node-image/entrypoint.sh /var/lib/tensor/

# clamav
ADD  clamav/clamav.tgz /var/lib/

# avira
ADD avira/savapi-sdk-linux64.tgz /usr/local
COPY configs/node-image/savapi.conf /etc/savapi/savapi.conf

ENTRYPOINT ["/var/lib/tensor/entrypoint.sh"]
