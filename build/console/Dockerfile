FROM ubuntu:20.04

ADD dist/console /
ADD configs/data/policy /policy

COPY configs/kube-scanner/translate.json /kube-scanner/translate.json
# TODO move to tensor-sherlock in the future
COPY dist/holmes-rules-v* /rules/

RUN apt-get update -y
RUN apt-get install -y ca-certificates

CMD /console
