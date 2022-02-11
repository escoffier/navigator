FROM busybox:1.31.0-glibc

ADD dist/console /
ADD configs/data/policy /policy

COPY configs/kube-scanner/translate.json /kube-scanner/translate.json


CMD /console
