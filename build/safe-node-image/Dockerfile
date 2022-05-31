FROM docker

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk update && apk upgrade \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY ./dist/safe-node-image /app
RUN chmod u+x safe-node-image

ENV GIN_MODE=release


ENTRYPOINT ["./safe-node-image"]
