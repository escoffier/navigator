FROM ubuntu:eoan

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libelf1 libtinfo5

WORKDIR /bcc
# aquasec/bcc-builder is built from the upstream bcc dockerfile using:
# docker build --target=builder -t aquasec/bcc-builder:latest --file Dockerfile.ubuntu .
# TODO: change this dependency
COPY --from=aquasec/bcc-builder:latest /root/bcc/libbcc_*.deb /bcc/
RUN DEBIAN_FRONTEND=noninteractive dpkg -i libbcc_*.deb && rm -rf /bcc

WORKDIR /
ADD dist/tensordig /

CMD /tensordig
