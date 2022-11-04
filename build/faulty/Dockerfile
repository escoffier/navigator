ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/baseimage-faulty:${TAG}

ADD configs/faulty /app
ADD test/ /test
# RUN useradd tomcat
# USER tomcat
# WORKDIR /test/ltp

# RUN make autotools
# RUN ./configure
# RUN make && make install

CMD ["/app/entrypoint.sh"]