FROM python:3.8-alpine

ARG MIRROR=archive.ubuntu.com
RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list

RUN apk --update add gcc build-base libffi-dev openssl-dev
RUN pip3 install --no-cache-dir elastalert

CMD elastalert
