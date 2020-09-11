FROM busybox:1.31.0-glibc

ADD dist/vegeta-console /
ADD dist/ui /ui
ADD testdata /testdata
ADD configs/scap/jobs /jobs

CMD /vegeta-console
