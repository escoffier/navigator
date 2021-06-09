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
    -o /vegeta/drift-prevention gitlab.com/piccolo_su/vegeta/cmd/drift-prevention

ENTRYPOINT ["/vegeta/drift-prevention"]
