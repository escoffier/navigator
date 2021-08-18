# Note - container OS does *not* need to be the same as scanned host's OS. 
FROM golang:1.15.0 AS build

ARG GOPROXY=
RUN export GOPROXY=$GOPROXY

WORKDIR /go/src/app

COPY bench-tool/go.mod .
COPY bench-tool/go.sum .
COPY bench-tool/main.go .
COPY bench-tool/database.go .
COPY bench-tool/run.go .

ENV GOPROXY="https://goproxy.io"
RUN GO111MODULE=on CGO_ENABLED=0 go install -a


FROM registry.t-appagile.com/tensorsecurity/baseimage-host-bench:latest

ADD xccdfparser xccdfparser/

RUN cd xccdfparser \
    && pip3 install -r requirements.txt . -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && cd - \

# Prefetch remote resources for CentOS8: https://bugzilla.redhat.com/show_bug.cgi?id=1851375
# It actually uses redhat data.
    && curl -o security-data-oval-com.redhat.rhsa-RHEL8.xml https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml \
    && sed "s#https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml#file:security-data-oval-com.redhat.rhsa-RHEL8.xml#g" /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml > ssg-rhel8-offline-ds.xml \
# .. for CentOS7
    && curl -o security-data-oval-com.redhat.rhsa-RHEL7.xml https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml \
    && sed "s#https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml#file:security-data-oval-com.redhat.rhsa-RHEL7.xml#g" /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml > ssg-rhel7-offline-ds.xml

ADD tailoring-file-centos.xml tailoring/

COPY --from=build /go/bin/bench-tool .

ADD entrypoint.sh .

ADD add_translations.py .
ADD translations.json .

CMD ["./entrypoint.sh"]
