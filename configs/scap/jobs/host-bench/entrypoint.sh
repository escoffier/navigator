#!/bin/bash

# Source host's OS information
source /mnt/root/etc/os-release

# Examples:
# NAME="Ubuntu Core"
# VERSION_ID="16"
#
# NAME=Fedora
# VERSION_ID=31
#
# NAME="CentOS Linux"
# VERSION_ID="8"

case $NAME in 
  *Ubuntu*)
    DS_STR="ubuntu${VERSION_ID}04"
  ;;
  *CentOS*)
    DS_STR="centos${VERSION_ID}"
  ;;
  *)
    echo "Unsupported OS: $NAME"
    exit 1
  ;;
esac

DSPATH="/usr/share/xml/scap/ssg/content/ssg-$DS_STR-xccdf.xml"
PROFILE="standard"

echo "Using datasource $DSPATH"
echo "Using profile $PROFILE"

echo "Running oscap-chroot"
oscap-chroot /mnt/root/ xccdf eval --report=report.html --results=results.xccdf --profile=standard /usr/share/xml/scap/ssg/content/ssg-ubuntu1804-xccdf.xml > stdout.txt
# oscap-chroot /mnt/root/ xccdf eval --report=report.html --results=results.xccdf --profile=$PROFILE $DSPATH > stdout.txt
retval=$?
if [ $retval -ne 0 ]; then
  exit $retval
fi

echo "Running xccdfparser"
xccdfparser -o ./out.json ./results.xccdf
retval=$?
if [ $retval -ne 0 ]; then
  exit $retval
fi

echo "Converting output json to mongo record: Node name: $NODE_NAME, Check ID: $CHECK_ID"
jq -n \
    --arg nodeName "$NODE_NAME" \
    --argjson timestamp $(date +%s) \
    --arg checkid "$CHECK_ID" \
    --slurpfile resultsData \
    out.json \
    '{"checkId": $checkid, "nodeName": $nodeName, "status": "completed", "finishedAt": $timestamp, "results": $resultsData}' > record.json
retVal=$?
if [ $retVal -ne 0 ]; then
    exit $retVal
fi

echo "Importing record to mongo"
mongoimport record.json --uri $MONGO_STRING --collection "host-bench-records" --mode=merge --upsertFields=checkId,nodeName
retVal=$?
if [ $retVal -ne 0 ]; then
  exit $retVal
fi
exit 0
