FROM busybox:1.31.0-glibc

WORKDIR /app

COPY ./dist/webshell-server /app
RUN chmod u+x webshell-server

ENV GIN_MODE=release

CMD ["./webshell-server"]
