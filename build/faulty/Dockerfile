ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/drift-prevention-client:${TAG} AS drift-prevention
FROM ${REPO}/baseimage-faulty:${TAG}

ADD configs/faulty /app
ADD test/ /test
# RUN useradd tomcat
# USER tomcat
# WORKDIR /test/ltp

# RUN make autotools
# RUN ./configure
# RUN make && make install

COPY --from=drift-prevention /drift-prevention/ubuntu/dp.so /tmp/dp.so
COPY --from=drift-prevention /drift-prevention/file-checker /tmp/file-checker

RUN /tmp/file-checker

CMD ["/app/entrypoint.sh"]