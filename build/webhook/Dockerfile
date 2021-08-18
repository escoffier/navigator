FROM busybox:1.31.0-glibc

LABEL maintainer="tensorsec"

ADD dist/webhook /go/bin/

ENTRYPOINT ["/go/bin/webhook"]
