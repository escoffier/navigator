FROM alpine

ARG MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s/dl-cdn.alpinelinux.org/${MIRROR}/g" /etc/apk/repositories

RUN apk update
RUN apk add --no-cache mongodb-tools jq

ADD configs/audit/ /app

CMD /app/entrypoint.sh
