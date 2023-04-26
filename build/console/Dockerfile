FROM ubuntu:20.04

ADD dist/console /
ADD configs/data/policy /policy

COPY configs/kube-scanner/translate.json /kube-scanner/translate.json
# TODO move to tensor-sherlock in the future
COPY dist/holmes-rules-v* /rules/

RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && apt-get update -y \
    && apt-get install -y ca-certificates \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD /console
