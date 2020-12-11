yesterday=$(date +"%Y-%m-%d" -d@"$(( `date +%s`-86400))")
echo "Doing $yesterday."

if [ ! -d /audits/$yesterday ]; then
    today=$(date +"%Y-%m-%d")
    for coll in alerts assets-containers audit cluster docker-bench-records host-bench-records kube-bench-records rules scantasks CVE2CNNVD checkHistoryEntry vulnerabilitiesInImages
    do
     	echo "Doing $coll. Dumping data between ${yesterday}:00.00.00 and ${today}:00.00.00"
        mongodump --quiet --uri mongodb://$TENSORSEC_MONGO_USER:$TENSORSEC_MONGO_PASSWORD@$TENSORSEC_MONGO_ADDRESS:$TENSORSEC_MONGO_PORT/$TENSORSEC_MONGO_AUTH_SOURCE --gzip -o /audits/$yesterday -c $coll --query "{\"historicised_timestamp\":{\"\$gt\":{\"\$date\":`date -d $yesterday +%s`000},\"\$lt\":{\"\$date\":`date -d $today +%s`000}}}"
        if [ $? -eq 0 ]
        then
            echo "Dump $coll-$yesterday suceeded."
        else
            echo "Dump $coll-$yesterday failed."
        fi
    done
fi
