#!/bin/bash
for i in {1..200}
do
sed -e "s|drift1|drift$i|g" -e "s^harbor.tensorsecurity.com/test/drift:1^harbor.tensorsecurity.com/test/drift:$i^g" drift1.yaml |kubectl apply -f - --namespace test

#Uncomment int command to delete
# sed -e "s|drift1|drift$i|g" -e "s^harbor.tensorsecurity.com/test/drift:1^harbor.tensorsecurity.com/test/drift:$i^g" drift1.yaml |kubectl delete -f - --namespace test


done

