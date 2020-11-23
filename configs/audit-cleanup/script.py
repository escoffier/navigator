from datetime import datetime, timedelta
import os
import shutil
import sys

from pymongo import MongoClient

user = os.environ['TENSORSEC_MONGO_USER']
password = os.environ['TENSORSEC_MONGO_PASSWORD']
address = os.environ['TENSORSEC_MONGO_ADDRESS']
port = os.environ['TENSORSEC_MONGO_PORT']
auth_source = os.environ['TENSORSEC_MONGO_AUTH_SOURCE']

client = MongoClient("mongodb://%s:%s@%s:%s/?authSource=%s" % (
    user, password, address, port, auth_source
))

audit_configuration = client.vegeta.audit.find_one({"deleted_at": {"$exists": False}})
last_cold_days_limit = audit_configuration['coldStorageDays']
last_cold_date = datetime.today().replace(hour=0,minute=0,second=0,microsecond=0) - timedelta(days=last_cold_days_limit)
print("Cold storage days limit: %d" % last_cold_days_limit)

backups = sorted(os.listdir('/audits'))

print("Removing backups older than ", last_cold_date)
for d in backups:
    backup_date = datetime.strptime(d, "%Y-%m-%d")
    print("Currently checking ", backup_date)
    if backup_date < last_cold_date:
        print("Removing %s as exceeding supported cold storage date %s" % (d, last_cold_date))
        shutil.rmtree('/audits/%s' % d)