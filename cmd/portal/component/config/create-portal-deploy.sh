#!/bin/zsh

kubectl -n tensorsec delete cm   portal-config
kubectl -n tensorsec delete -f  portal-nginx-config.yaml
kubectl -n tensorsec create configmap portal-config --from-file=portal-config.yaml
kubectl -n tensorsec apply -f portal-nginx-config.yaml

kubectl -n tensorsec delete -f portal-backend.yaml
kubectl -n tensorsec delete -f  portal-frontend.yaml

kubectl -n tensorsec apply -f  portal-backend.yaml
kubectl -n tensorsec apply -f  portal-frontend.yaml