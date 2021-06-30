#!/usr/bin/env bash

sudo ./webhook-create-signed-cert.sh \
--service tensorsec-image-validator \
--secret tensorsec-webhook-certs \
--namespace tensorsec-test-cn

sudo cat validatingwebhook-manual.yaml | \
./webhook-patch-ca-bundle.sh > \
validatingwebhook-ca-bundle.yaml

kubectl apply -f validatingwebhook-ca-bundle.yaml