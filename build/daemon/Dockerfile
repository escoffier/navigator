FROM centos:7

## 配置国内yum源
RUN mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak && \
    curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo && \
    curl -o /etc/yum.repos.d/epel.repo https://mirrors.aliyun.com/repo/epel-7.repo
#RUN yum install -y epel-release
RUN yum install -y supervisor

COPY bin/daemon /
COPY bin/ns-mnt /
COPY ./configs/daemon/supervisord.conf /etc/

CMD ["supervisord"]
