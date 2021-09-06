ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/baseimage-scanner:${TAG}

ADD dist/tensor-scanner /
ADD configs/scanner /configs/scanner/

CMD /tensor-scanner