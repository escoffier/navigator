FROM registry.t-appagile.com/tensorsecurity/baseimage-holmes:latest

COPY ./configs/holmes/docker-entrypoint.sh /
COPY ./configs/holmes/holmes_export.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/holmes"]