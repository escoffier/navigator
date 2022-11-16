FROM ubuntu:20.04

ARG TAG=latest
RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && apt-get update -y \
    && apt-get full-upgrade -y \
    && apt-get install -y clamav \
    && sed -i "s|ReceiveTimeout 30|ReceiveTimeout 300|" /etc/clamav/freshclam.conf \
    && sed -i "s|MaxAttempts 5|MaxAttempts 3|" /etc/clamav/freshclam.conf \
    && sed -i "s|DatabaseMirro.*|DatabaseMirror db.cn.clamav.net|" /etc/clamav/freshclam.conf \
    && freshclam \
    && apt-get install -y clamav-daemon \
    && update-rc.d clamav-daemon defaults 99 \
    && apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common \
    && curl -fsSL https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg | apt-key add - \
    && add-apt-repository "deb [arch=$(dpkg --print-architecture)] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu $(lsb_release -cs) stable" \
    && apt-get install -y  docker-ce-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ADD dist/scanner /
ADD configs/scanner /configs/scanner/

CMD /scanner
