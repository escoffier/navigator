FROM ubuntu:18.04

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ARG MIRROR=archive.ubuntu.com
RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list
RUN sed -i "s!security.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends \
	ca-certificates build-essential wget auditd audispd-plugins git

WORKDIR /tmp

RUN wget https://dl.google.com/go/go1.13.9.linux-amd64.tar.gz
RUN tar xf go1.13.9.linux-amd64.tar.gz

WORKDIR /go/src/app
COPY . .

WORKDIR /go/src/app/pkg

RUN PATH=$PATH:/tmp/go/bin go mod init gitlab.com/tensorsec/pkg

WORKDIR /go/src/app/cmd/go-audit

RUN PATH=$PATH:/tmp/go/bin GO111MODULE=on go build -v -a \
	-o /go/src/app/dist/go-audit gitlab.com/tensorsec/go-audit

CMD /go/src/app/dist/go-audit -config config.yaml
