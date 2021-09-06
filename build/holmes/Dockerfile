ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/baseimage-holmes:${TAG}

COPY ./configs/holmes/docker-entrypoint.sh /
COPY ./configs/holmes/holmes_export.sh /
COPY ./dist/holmes-rules-update /
# COPY ./configs/holmes/rules/holmes_rules.yaml /etc/holmes/holmes_rules.yaml
COPY ./dist/tensorsec-holmes-rules.thr /etc/holmes/tensorsec-holmes-rules.thr

ENTRYPOINT ["/docker-entrypoint.sh"]

#CMD ["/usr/bin/holmes"]