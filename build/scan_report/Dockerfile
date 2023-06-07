FROM ubuntu:20.04

RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && apt-get update && apt-get install -y zip unzip curl wget lsof &&  apt-get full-upgrade -y \
    && apt-get clean \
    && apt-get install -y libclamav-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./dist/scan_report /app
RUN chmod u+x scan_report

CMD ["./scan_report"]
