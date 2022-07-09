FROM busybox:1.31.0-glibc

ADD dist/cluster-proxy /go/bin/

ENTRYPOINT ["/go/bin/cluster-proxy"]
