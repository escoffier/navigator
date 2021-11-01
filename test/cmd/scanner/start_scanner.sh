#!/bin/bash

#migrate
#migratecmd="/Users/lingximo/go/src/github.com/golang-migrate/migrate/cli/build/migrate.darwin-amd64"
#${migratecmd} -verbose -source file:///Users/lingximo/go/src/gitlab.com/tensorsecurity-rd/db-migrate/postgres -database "postgres://postgres:password@localhost:5432/postgres?sslmode=disable&x-migrations-table=migrations_record" up

env CICD-BUF-REGISTRY-URL=http://localhost:5000 \
CICD-BUF-REGISTRY-USER=testuser \
CICD-BUF-REGISTRY-PASSWORD=testpassword \
SAFENODE-BUF-REGISTRY-URL=http://localhost:5000 \
SAFENODE-BUF-REGISTRY-USER=testuser \
SAFENODE-BUF-REGISTRY-PASSWORD=testpassword \
SAFENODE-BUF-INTERNA=10 \
./dist/tensor-scanner --image-cache-server-ip="localhost" --image-cache-server-port=9278 \
--redis-endpoint="localhost:26379,localhost:26380"  --redis-password="123456" \
--http-listen-addr=":8082" \
--db-connect-str="postgres://postgres:password@localhost:5432/postgres?sslmode=disable" \
--pvc-path="./ti-db/" \
--parallel-subtask-num=1
