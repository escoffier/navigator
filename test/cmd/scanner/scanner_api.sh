#!/bin/bash

#add registry
#curl -v -XPOST "http://localhost:8080/api/v1/register/registry" -d@scanner_api_data.json

#scan one
curl -v -XPOST "http://localhost:8080/api/v1/scan/scanone" -d@scanner_scan_one.json

