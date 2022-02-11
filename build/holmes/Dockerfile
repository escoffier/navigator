ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/baseimage-holmes:${TAG}

# RUN apt-get update -y && apt --fix-broken install -y && apt-get install supervisor -y

COPY ./configs/holmes/docker-entrypoint.sh /
COPY ./dist/holmes-scheduler /
COPY ./dist/holmes-rules.thr /

ENTRYPOINT ["/docker-entrypoint.sh"]