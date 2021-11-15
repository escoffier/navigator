FROM busybox:1.31.0-glibc

ADD dist/webhook /go/bin/

ENTRYPOINT ["/go/bin/webhook"]
