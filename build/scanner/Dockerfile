ARG MIRROR=archive.ubuntu.com
ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/drift-prevention-client:${TAG} AS drift-prevention
FROM ${REPO}/baseimage-scanner:${TAG}


COPY --from=drift-prevention /drift-prevention/ubuntu/dp.so /config/dp.so
COPY --from=drift-prevention /drift-prevention/file-checker /config/file-checker

ADD dist/scanner /
ADD configs/scanner /configs/scanner/

CMD /scanner
