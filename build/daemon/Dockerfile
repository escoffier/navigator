FROM python:3.7.5

ADD nodemon/daemon/dist /

RUN pip install *.tar.gz && rm -f *.tar.gz

CMD ["python", "-u", "/usr/local/bin/vegeta-daemon"]
