FROM registry.t-appagile.com/tensorsecurity/baseimage-drift-prevention-client:latest

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ADD configs/drift-prevention/ld-preload /drift-prevention

ADD cmd/file-checker /go/src/app

WORKDIR /go/src/app
COPY . .

RUN GO111MODULE=on go build -v -a \
    -o /drift-prevention/file-checker gitlab.com/piccolo_su/vegeta/cmd/file-checker && rm -rf /go/src/app

FROM golang:1.16.5-alpine3.14
COPY --from=0 /drift-prevention/file-checker /drift-prevention/file-checker

CMD ["tail", "-f", "/dev/null"]