FROM alpine

ARG MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s/dl-cdn.alpinelinux.org/${MIRROR}/g" /etc/apk/repositories
RUN apk update && apk add --no-cache mongodb-tools postgresql-client
COPY dist/tensor-cleaner /app/tensor-cleaner
COPY configs/data/jobs/hot-logic/hot-logic-conf.json /app/hot-logic-conf.json
COPY configs/data/jobs/hot-offline/hot-offline-conf.json /app/hot-offline-conf.json
CMD /app/tensor-cleaner
