FROM busybox:1.31.0-glibc

ADD dist/kafka-proxy /go/bin/

ENTRYPOINT ["/go/bin/kafka-proxy"]
