FROM alpine:3.12

LABEL maintainer="tensorsec"

# copy the go binaries from the building stage

ADD dist/image-validator /go/bin

ENTRYPOINT ["/go/bin/image-validator"]