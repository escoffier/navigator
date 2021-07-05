FROM registry.t-appagile.com/tensorsecurity/baseimage-drift-prevention:latest

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

ADD cmd/drift-prevention /go/src/app

WORKDIR /go/src/app
COPY . .

RUN rm -rf go.mod go.sum

COPY configs/drift-prevention/webhook/go.mod .
COPY configs/drift-prevention/webhook/go.sum .

RUN GO111MODULE=on go build -v -a \
    -o /vegeta/drift-prevention gitlab.com/piccolo_su/vegeta/cmd/drift-prevention && rm -rf /go/src/app

FROM golang:1.16.5-alpine3.14
COPY --from=0 /vegeta/drift-prevention /vegeta/drift-prevention


ENTRYPOINT ["/vegeta/drift-prevention"]
