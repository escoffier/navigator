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
  *CentOS*)
    # Use offline ds (use resources prefetched during dockerfile build)
    DSPATH="./ssg-rhel$VERSION_ID-offline-ds.xml"
    TAILORINGPATH="./tailoring/tailoring-file-centos.xml"
    # PROFILE="xccdf_org.ssgproject.content_profile_standard"

    echo "DSPATH=$DSPATH"
    ecoh "TAILORINGPATH=$TAILORINGPATH"

    echo "Running oscap-chroot"
    oscap-chroot /mnt/root/ xccdf eval --tailoring-file $TAILORINGPATH --report=report.html --results=results.xccdf --profile xccdf_org.tensorsecurity.content_profile_unselect_memory_intensive_from_standard $DSPATH

    # retval == 0, when no error, passed all rules
    # retval == 2, when no error, failed some rules
    if [[ $retval -eq 1 ]]; then
      exit $retval
    fi
  ;;
  *)
    echo "Unsupported OS: $NAME"
    exit 1
  ;;
esac


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
    --argfile resultsData \
    out.json \
    '{"checkId": $checkid, "nodeName": $nodeName, "status": "completed", "finishedAt": $timestamp, "report": $resultsData}' > record.json
retVal=$?
if [ $retVal -ne 0 ]; then
    exit $retVal
fi

echo "Importing record to mongo"
mongoimport record.json --uri $(eval echo $MONGO_STRING) --collection "host-bench-records" --mode=merge --upsertFields=checkId,nodeName
retVal=$?
if [ $retVal -ne 0 ]; then
  exit $retVal
fi
exit 0
