# Troubleshooting

**After redeploying/upgrading the cluster, "Compliance check history" screen shows no results. However, I can schedule a check using "Start" button.**

A race condition may have occured on MongoDB between Compliance check job and Console(Navigator).
Compliance check job updates existing MongoDB entry. But if a compliance check job started before the teardown and finished after new setup, it will update a non-existing entry.
This entry will be in bad state, missing initial fields.

Compliance check jobs are not cleaned up during helm upgrades.

To clean them up manually, use
```bash
kubectl --namespace tensorsec get job --namespace tensorsec | grep "-bench" | awk '{print $2}' | xargs kubectl --namespace tensorsec delete job
```

Note: `make redeploy` target actually does this but is not meant for production environments.

---