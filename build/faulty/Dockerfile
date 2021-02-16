FROM registry.t-appagile.com/tensorsecurity/tensorsec-drift-prevention-client:latest AS drift-prevention
FROM ubuntu:18.04

ARG MIRROR=archive.ubuntu.com
RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
    gcc \
    make \
    sudo \
    golang-1.10 \
    vim \
    netcat \
    net-tools \
    strace \
    software-properties-common \
    python3.6 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/lib/go-1.10/bin:$PATH"

ADD configs/faulty /app
ADD test/ /test

COPY --from=drift-prevention /drift-prevention/ubuntu/dp.so /tensorsec/dp.so
COPY --from=drift-prevention /drift-prevention/file-checker /tensorsec/file-checker

RUN /tensorsec/file-checker

CMD ["/app/entrypoint.sh"]
