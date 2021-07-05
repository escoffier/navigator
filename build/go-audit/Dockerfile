FROM registry.t-appagile.com/tensorsecurity/baseimage-go-audit:latest

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

WORKDIR /go/src/app
COPY . .

WORKDIR /go/src/app/pkg

RUN PATH=$PATH:/tmp/go/bin go mod init gitlab.com/tensorsec/pkg

WORKDIR /go/src/app/cmd/go-audit

RUN PATH=$PATH:/tmp/go/bin GO111MODULE=on go build -v -a \
	-o /go/src/app/dist/go-audit gitlab.com/tensorsec/go-audit && rm -rf /go/src/app

FROM golang:1.16.5-alpine3.14
COPY --from=0 /go/src/app/dist/go-audit /go/src/app/dist/go-audit

CMD /go/src/app/dist/go-audit -config config.yaml
