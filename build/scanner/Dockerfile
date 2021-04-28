FROM ubuntu:18.04
ARG MIRROR=archive.ubuntu.com

RUN sed -i "s!archive.ubuntu.com/!${MIRROR}/!g" /etc/apt/sources.list && apt-get update -y && apt-get install -y clamav && sed -i "s|ReceiveTimeout 30|ReceiveTimeout 300|" /etc/clamav/freshclam.conf && sed -i "s|MaxAttempts 5|MaxAttempts 3|" /etc/clamav/freshclam.conf && sed -i "s|DatabaseMirro.*|DatabaseMirror db.cn.clamav.net|" /etc/clamav/freshclam.conf && freshclam && apt-get install -y clamav-daemon && update-rc.d clamav-daemon defaults 99

ADD dist/tensor-scanner /
ADD configs/scanner /configs/scanner/

CMD /tensor-scanner
