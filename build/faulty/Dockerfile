from ubuntu:18.04

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
    software-properties-common \
    python3.6 \
    && rm -rf /var/lib/apt/lists/*

RUN export PATH="/usr/lib/go-1.10/bin:$PATH"

ADD test/ /test

CMD ["/bin/sh"]
