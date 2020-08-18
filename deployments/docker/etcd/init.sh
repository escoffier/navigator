#!/bin/sh

BASEDIR=$(dirname "$0")
SERVER=etcd:2379

cat "$BASEDIR/scanner_clair.yaml" | etcdctl --endpoints=$SERVER put /scanner/clair.yaml
cat "$BASEDIR/scanner_db.yaml" | etcdctl --endpoints=$SERVER put /scanner/db.yaml

sleep infinity
