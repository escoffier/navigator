FROM python:3.8-alpine

RUN apk --update add gcc build-base libffi-dev openssl-dev
RUN pip3 install --no-cache-dir elastalert

CMD elastalert
