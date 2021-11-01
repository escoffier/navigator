ARG MIRROR=archive.ubuntu.com
ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
ARG TAGG=testcn
FROM ${REPO}/tensorsec-drift-prevention-client:${TAGG} AS drift-prevention
FROM ${REPO}/baseimage-scanner:${TAG}


COPY --from=drift-prevention /drift-prevention/ubuntu/dp.so /tensorsec/dp.so
COPY --from=drift-prevention /drift-prevention/file-checker /tensorsec/file-checker

ADD dist/tensor-scanner /
ADD configs/scanner /configs/scanner/

CMD /tensor-scanner
