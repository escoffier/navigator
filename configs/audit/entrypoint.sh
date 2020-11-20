d=$(date +"%Y-%m-%d" -d@"$(( `date +%s`-86400))")
echo "Doing $d."

if [ ! -d /audits/$d ]; then
    d2=$(date +"%Y-%m-%d" -d@"$(( `date +%s`-$((2 * 86400))))")
    for coll in alerts assets-containers audit cluster docker-bench-records host-bench-records kube-bench-records rules scantasks
    do
     	echo "Doing $coll."
        mongodump --quiet --uri mongodb://$TENSORSEC_MONGO_USER:$TENSORSEC_MONGO_PASSWORD@$TENSORSEC_MONGO_ADDRESS:$TENSORSEC_MONGO_PORT/$TENSORSEC_MONGO_AUTH_SOURCE --gzip -o /audits/$d -c $coll --query "{\"auditedentry.audit_timestamp\":{\"\$gt\":{\"\$date\":`date -d $d +%s`000},\"\$lt\":{\"\$date\":`date -d $d2 +%s`000}}}"
        if [ $? -eq 0 ]
        then
            echo "Dump $coll-$d suceeded."
        else
            echo "Dump $coll-$d failed."
        fi
    done
fi
