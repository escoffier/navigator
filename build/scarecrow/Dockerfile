FROM redis:6.2.4 AS redis

FROM registry.t-appagile.com/tensorsecurity/baseimage-scarecrow:latest

COPY --from=redis /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY ./configs/scarecrow/run.sh /
COPY ./configs/scarecrow/.docker/ /usr/local/apache-tomcat-8.5.70/webapps/ROOT/.docker/

CMD ["/run.sh"] 

