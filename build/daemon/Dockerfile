FROM ubuntu:20.04

## 配置国内yum源

RUN apt-get update
RUN apt-get install supervisor -y
RUN apt-get install libdevmapper-dev -y
RUN apt-get install libgpgme-dev -y
RUN export DEBIAN_FRONTEND=noninteractive && apt-get install libglib2.0-dev -y

COPY bin/daemon /
COPY bin/ns-mnt /
COPY ./configs/daemon/supervisord.conf /etc/
COPY ./configs/drift-prevention/inject /

CMD ["supervisord"]
