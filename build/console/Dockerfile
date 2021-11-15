FROM busybox:1.31.0-glibc

ADD dist/console /
ADD configs/data/policy /policy
ADD ./tensor-compliance-check /jobs
COPY configs/data/jobs/hot-logic/job.yaml /jobs/hot-logic/job.yaml
COPY configs/data/jobs/hot-offline/job.yaml /jobs/hot-offline/job.yaml
COPY configs/data/jobs/cold/job.yaml /jobs/cold/job.yaml

COPY configs/kube-hunter/job.yaml /jobs/kube-hunter/job.yaml
COPY configs/kube-hunter/translate.json /kube-hunter/translate.json

COPY configs/platform-report/job.yaml /jobs/platform-report/job.yaml

CMD /console
