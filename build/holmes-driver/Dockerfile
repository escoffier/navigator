FROM nginx:alpine
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk update && apk upgrade \
    && rm -rf /var/cache/apk/*
RUN rm -rf /usr/share/nginx/html/* && mkdir -p /usr/share/nginx/html/319368f1ad778691164d33d59945e00c5752cd27/ && chmod -R 755 /usr/share/nginx/html/
COPY holmes_* /usr/share/nginx/html/319368f1ad778691164d33d59945e00c5752cd27/
RUN chmod 644 /usr/share/nginx/html/319368f1ad778691164d33d59945e00c5752cd27/holmes_*
