ARG TAG=latest
FROM registry.t-appagile.com/tensorsecurity/tensorsec-drift-prevention-client:${TAG} AS drift-prevention
FROM registry.t-appagile.com/tensorsecurity/baseimage-faulty:latest

ADD configs/faulty /app
ADD test/ /test

# WORKDIR /test/ltp

# RUN make autotools
# RUN ./configure
# RUN make && make install

COPY --from=drift-prevention /drift-prevention/ubuntu/dp.so /tensorsec/dp.so
COPY --from=drift-prevention /drift-prevention/file-checker /tensorsec/file-checker

RUN /tensorsec/file-checker

CMD ["/app/entrypoint.sh"]