FROM redis:6.2.4 AS redis

FROM registry.t-appagile.com/tensorsecurity/baseimage-canary:latest

COPY --from=redis /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY ./configs/canary/run.sh /
COPY ./configs/canary/.docker/ /var/www/html/

CMD ["/run.sh"] 

