FROM alpine

ARG MIRROR_SOURCE=mirrors.ustc.edu.cn

RUN sed -i "s/dl-cdn.alpinelinux.org/${MIRROR_SOURCE}/g" /etc/apk/repositories \
    && apk update \
    && apk upgrade \
    && apk add --no-cache mysql-client \
    && rm -rf /var/cache/apk/*
COPY dist/cleaner /app/cleaner
COPY configs/data/jobs/hot-logic/hot-logic-conf.json /app/hot-logic-conf.json
COPY configs/data/jobs/hot-offline/hot-offline-conf.json /app/hot-offline-conf.json
CMD /app/cleaner
