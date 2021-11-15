FROM busybox:1.31.0-glibc

WORKDIR /app

COPY ./dist/scan_report /app
RUN chmod u+x scan_report

CMD ["./scan_report"]
