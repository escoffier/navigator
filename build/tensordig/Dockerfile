FROM registry.t-appagile.com/tensorsecurity/baseimage-tensordig:latest

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

WORKDIR /bcc

COPY configs/tensordig/bcc bcc
RUN mkdir bcc/build

WORKDIR /bcc/bcc/build
RUN cmake ..
RUN make
RUN make install

WORKDIR /go/src/app
COPY . .

RUN git config --global url."git@gitlab.com".insteadOf "https://gitlab.com"
RUN PATH=$PATH:/tmp/go/bin GO111MODULE=on GOPRIVATE="gitlab.com/tensorsecurity-rd" go build -v -a \
	-o dist/tensordig gitlab.com/piccolo_su/vegeta/cmd/tensordig
# Be careful when adding LDFLAGS because they conflict with CGO
# Remove them for now.
# --ldflags "$LDFLAGS -X gitlab.com/piccolo_su/vegeta/cmd/tensordig/cmd.Version=$VERSION" \ 

CMD configs/tensordig/entrypoint.sh
