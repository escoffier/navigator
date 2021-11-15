ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/baseimage-data:${TAG}

COPY dist/cleaner /app/cleaner
COPY configs/data/jobs/hot-logic/hot-logic-conf.json /app/hot-logic-conf.json
COPY configs/data/jobs/hot-offline/hot-offline-conf.json /app/hot-offline-conf.json
CMD /app/cleaner
