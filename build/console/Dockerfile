FROM busybox:1.31.0-glibc

ADD dist/console /
ADD configs/data/policy /policy

COPY configs/kube-scanner/translate.json /kube-scanner/translate.json
# TODO move to tensor-sherlock in the future
COPY dist/holmes-rules-v* /rules/

CMD /console
