FROM golang:1.15-alpine3.12

WORKDIR /go/src/gitlab.com/piccolo_su/vegeta

COPY ./cmd/webhook /go/src/gitlab.com/piccolo_su/vegeta/cmd/webhook
COPY ./go.mod .
COPY . /go/src/gitlab.com/piccolo_su/vegeta/
ENV GOPROXY https://goproxy.cn
ENV GO111MODULE on
ENV CGO_ENABLED 0
RUN  go mod download
RUN  go build -o /go/bin/webhook main.go && rm -rf /go/src/gitlab.com/piccolo_su/vegeta

FROM alpine:3.12

LABEL maintainer="tensorsec"

# copy the go binaries from the building stage
COPY --from=0 /go/bin /go/bin

#EXPOSE 443

ENTRYPOINT ["/go/bin/webhook"]