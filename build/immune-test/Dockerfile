FROM busybox:1.31.0-glibc

RUN touch /test.sh
COPY ./dist/immune-test /immune-test
COPY ./dist/immune-test-1.txt /tdata/1.txt
COPY ./dist/immune-test-2.txt /tdata/2.txt
CMD /immune-test
