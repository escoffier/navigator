FROM centos:7

RUN yum -y update
RUN yum install -y epel-release
RUN yum install -y supervisor

COPY bin/daemon /
COPY bin/ns-mnt /
COPY ./configs/daemon/supervisord.conf /etc/

CMD ["supervisord"]
