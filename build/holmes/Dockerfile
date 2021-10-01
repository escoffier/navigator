ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/baseimage-holmes:${TAG}

COPY ./configs/holmes/docker-entrypoint.sh /

COPY ./dist/holmes-scheduler /

COPY ./dist/tensorsec-holmes-rules.thr /

ENTRYPOINT ["/docker-entrypoint.sh"]

#CMD ["/usr/bin/holmes"]