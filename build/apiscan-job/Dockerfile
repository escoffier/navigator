FROM busybox:1.31.0-glibc

COPY ./xray /usr/local/bin/xray

COPY configs/apiscan-job/xray-config.yaml /app/config.yaml

COPY dist/apiscan /app/apiscan
WORKDIR /app
ENTRYPOINT ["./apiscan"]