FROM registry.t-appagile.com/tensorsecurity/tensorsec-drift-prevention-client:test AS drift-prevention
FROM ubuntu:18.04

ARG MIRROR=archive.ubuntu.com
RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
    automake \
    gcc \
    make \
    sudo \
    golang-1.10 \
    vim \
    netcat \
    net-tools \
    strace \
    software-properties-common \
    curl \
    python3.6 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -o /tmp/docker-19.03.9.tgz https://download.docker.com/linux/static/stable/x86_64/docker-19.03.9.tgz

ENV PATH="/usr/lib/go-1.10/bin:$PATH"

ADD configs/faulty /app
ADD test/ /test

# WORKDIR /test/ltp

# RUN make autotools
# RUN ./configure
# RUN make && make install

COPY --from=drift-prevention /drift-prevention/ubuntu/dp.so /tensorsec/dp.so
COPY --from=drift-prevention /drift-prevention/file-checker /tensorsec/file-checker

RUN /tensorsec/file-checker

CMD ["/app/entrypoint.sh"]
