FROM python:3.8-alpine

ARG MIRROR=dl-cdn.alpinelinux.org
RUN sed -i "s!dl-cdn.alpinelinux.org/!${MIRROR}/!g" /etc/apk/repositories

RUN apk --update add gcc build-base libffi-dev openssl-dev
RUN pip3 install --no-cache-dir elastalert

CMD elastalert
