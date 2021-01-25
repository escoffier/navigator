FROM golang:1.13.5-alpine

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ARG MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s/dl-cdn.alpinelinux.org/${MIRROR}/g" /etc/apk/repositories

RUN apk update
RUN apk add --no-cache musl-dev gcc

ADD configs/drift-prevention/ld-preload /drift-prevention

ADD cmd/drift-prevention /go/src/app

WORKDIR /go/src/app
COPY . .

RUN GO111MODULE=on go build -v -a \
    -o /drift-prevention/file-checker gitlab.com/piccolo_su/vegeta/cmd/drift-prevention

CMD ["tail", "-f", "/dev/null"]
