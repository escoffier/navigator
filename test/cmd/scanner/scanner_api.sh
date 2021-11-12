#!/bin/bash

#add registry
#curl -v -XPOST "http://localhost:8082/api/v1/register/registry" -d@scanner_api_data.json

#scan one
#curl -v -XPOST "http://localhost:8082/api/v1/scan/scanone" -d@scanner_scan_one.json

#terminate task
#curl -v -XPUT "http://localhost:8082/api/v1/tasks/1/status" -d@task_data.json 
curl -v -H "Content-Type: application/json" -XPUT "http://localhost:8082/api/v1/tasks/1/status" -d '{"status":5}'
