FROM envoyproxy/envoy:v1.22.2

RUN apt-get update -y \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml"]
