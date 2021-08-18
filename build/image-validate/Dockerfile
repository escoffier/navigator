FROM busybox:1.31.0-glibc

LABEL maintainer="tensorsec"

# copy the go binaries from the building stage

ADD dist/image-validator /go/bin/

ENTRYPOINT ["/go/bin/image-validator"]
