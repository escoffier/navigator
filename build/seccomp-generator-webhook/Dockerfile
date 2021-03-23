FROM golang:1.15.5-alpine

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ARG MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s/dl-cdn.alpinelinux.org/${MIRROR}/g" /etc/apk/repositories

RUN apk update
RUN apk add --no-cache git musl-dev gcc

ADD cmd/seccomp-generator-webhook /go/src/app

WORKDIR /go/src/app
COPY . .

RUN rm -rf go.mod go.sum

COPY configs/seccomp-generator-webhook/go.mod .
COPY configs/seccomp-generator-webhook/go.sum .

RUN GO111MODULE=on go build -v -a \
    -o /vegeta/seccomp-generator-webhook gitlab.com/piccolo_su/vegeta/cmd/seccomp-generator-webhook

ENTRYPOINT ["/vegeta/seccomp-generator-webhook"]
