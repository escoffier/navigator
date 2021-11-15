FROM busybox:1.31.0-glibc

# copy the go binaries from the building stage

ADD dist/image-validator /go/bin/

ENTRYPOINT ["/go/bin/image-validator"]
