d=$(date +"%Y-%m-%d" -d@"$(( `date +%s`-86400))")
echo "Doing $d"
if [ ! -d /audits/$d ]; then
    d2=$(date +"%Y-%m-%d" -d@"$(( `date +%s`-$((2 * 86400))))")
    mongodump --quiet --uri mongodb://$TENSORSEC_MONGO_USER:$TENSORSEC_MONGO_PASSWORD@$TENSORSEC_MONGO_ADDRESS:$TENSORSEC_MONGO_PORT/$TENSORSEC_MONGO_AUTH_SOURCE --gzip -o /audits/$d -c rules --query "{\"deleted_at\":{\"\$gt\":{\"\$date\":`date -d $d +%s`000},\"\$lt\":{\"\$date\":`date -d $d2 +%s`000}}}"
    if [ $? -eq 0 ]
    then
        echo "Dump $d suceeded. Removing from hot storage"
    else
        echo "Dump $d failed. Not removing from hot storage"
    fi
fi
