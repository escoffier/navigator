FROM registry.t-appagile.com/tensorsecurity/baseimage-seccomp-generator-webhook:latest

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ADD cmd/seccomp-generator-webhook /go/src/app

WORKDIR /go/src/app
COPY . .

RUN rm -rf go.mod go.sum

COPY configs/seccomp-generator-webhook/go.mod .
COPY configs/seccomp-generator-webhook/go.sum .

RUN GO111MODULE=on go build -v -a \
    -o /vegeta/seccomp-generator-webhook gitlab.com/piccolo_su/vegeta/cmd/seccomp-generator-webhook && rm -rf /go/src/app

FROM golang:1.16.5-alpine3.14
COPY --from=0 /vegeta/seccomp-generator-webhook /vegeta/seccomp-generator-webhook

ENTRYPOINT ["/vegeta/seccomp-generator-webhook"]