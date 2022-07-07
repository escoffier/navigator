FROM ubuntu:18.04

RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && apt-get update && apt-get install -y zip unzip &&  apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./dist/scan_report /app
RUN chmod u+x scan_report

CMD ["./scan_report"]
