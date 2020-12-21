FROM ubuntu:18.04

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ARG MIRROR=archive.ubuntu.com
RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends \
	libelf1 libtinfo5 ca-certificates build-essential bison build-essential cmake flex git libedit-dev \
	libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev libfl-dev wget

WORKDIR /tmp

RUN wget https://dl.google.com/go/go1.13.9.linux-amd64.tar.gz
RUN tar xf go1.13.9.linux-amd64.tar.gz

WORKDIR /bcc

COPY configs/tensordig/bcc bcc
RUN mkdir bcc/build

WORKDIR /bcc/bcc/build
RUN cmake ..
RUN make
RUN make install

WORKDIR /go/src/app
COPY . .

RUN PATH=$PATH:/tmp/go/bin GO111MODULE=on go build -v -a \
	-o dist/tensordig gitlab.com/piccolo_su/vegeta/cmd/tensordig
# Be careful when adding LDFLAGS because they conflict with CGO
# Remove them for now.
# --ldflags "$LDFLAGS -X gitlab.com/piccolo_su/vegeta/cmd/tensordig/cmd.Version=$VERSION" \ 

CMD configs/tensordig/entrypoint.sh
