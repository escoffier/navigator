FROM ubuntu:18.04

WORKDIR /app

COPY ./dist/scan_report /app
RUN chmod u+x scan_report

CMD ["./scan_report"]
