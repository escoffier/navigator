FROM busybox:1.31.0-glibc

ADD dist/vegeta-scap /
ADD configs/scap /configs/scap/

CMD ['/vegata-scap', 'kubebench']
