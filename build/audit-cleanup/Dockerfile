FROM python:3.7-alpine

RUN pip install --no-cache-dir pymongo

ADD configs/audit-cleanup/ /app

CMD python3 /app/script.py
