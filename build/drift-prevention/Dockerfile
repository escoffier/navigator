FROM golang:1.12.5-alpine

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ARG MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s/dl-cdn.alpinelinux.org/${MIRROR}/g" /etc/apk/repositories

RUN apk update
RUN apk add --no-cache git musl-dev gcc

ADD cmd/drift-prevention /go/src/app

WORKDIR /go/src/app
COPY . .

RUN rm -rf go.mod go.sum

COPY configs/drift-prevention/webhook/go.mod .
COPY configs/drift-prevention/webhook/go.sum .

RUN GO111MODULE=on go build -v -a \
    -o /vegeta/drift-prevention gitlab.com/piccolo_su/vegeta/cmd/drift-prevention

ENTRYPOINT ["/vegeta/drift-prevention"]
