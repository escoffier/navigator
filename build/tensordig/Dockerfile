FROM ubuntu:eoan

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ARG MIRROR=archive.ubuntu.com
RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends \
        libelf1 libtinfo5 golang-1.13 ca-certificates build-essential

WORKDIR /bcc
# aquasec/bcc-builder is built from the upstream bcc dockerfile using:
# docker build --target=builder -t aquasec/bcc-builder:latest --file Dockerfile.ubuntu .
# TODO: change this dependency
COPY --from=aquasec/bcc-builder:latest /root/bcc/libbcc_*.deb /bcc/
RUN DEBIAN_FRONTEND=noninteractive dpkg -i libbcc_*.deb && rm -rf /bcc

WORKDIR /go/src/app
COPY . .


RUN PATH=$PATH:/usr/lib/go-1.13/bin GO111MODULE=on go build -v -a \
		-o dist/tensordig gitlab.com/piccolo_su/vegeta/cmd/tensordig
		# Be careful when adding LDFLAGS because they conflict with CGO
		# Remove them for now.
		# --ldflags "$LDFLAGS -X gitlab.com/piccolo_su/vegeta/cmd/tensordig/cmd.Version=$VERSION" \ 

CMD dist/tensordig
