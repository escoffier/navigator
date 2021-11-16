FROM busybox:1.31.0-glibc

COPY bin/daemon /
COPY bin/ns-mnt /

COPY ./configs/holmes/runnet.sh /

CMD ["sh", "/runnet.sh"]
