FROM mvertes/alpine-mongo:4.0.6-1

ARG MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s/dl-cdn.alpinelinux.org/${MIRROR}/g" /etc/apk/repositories

RUN apk update
RUN apk add --no-cache mongodb-tools=4.2.9-r0 jq

ADD configs/audit/ /app

CMD /app/entrypoint.sh
