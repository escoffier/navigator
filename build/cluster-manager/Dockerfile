FROM busybox:1.31.0-glibc

LABEL maintainer="tensorsec"

ADD dist/cluster-manager /go/bin/

ENTRYPOINT ["/go/bin/cluster-manager"]
