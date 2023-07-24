FROM envoyproxy/envoy:v1.22.2

ARG MIRROR_SOURCE=mirrors.aliyun.com

RUN sed -i "s!archive.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!${MIRROR_SOURCE}/!g" /etc/apt/sources.list \
    && apt-get update -y \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && apt install curl net-tools -y \
    && rm -rf /var/lib/apt/lists/*

COPY bootstrap.yaml /etc/envoy/bootstrap.yaml

CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/bootstrap.yaml"]
