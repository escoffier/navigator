#! /bin/bash

function alert() {
  req=$(jq -r  '. | {
    "RuleKey":{
        "Name": .rule,
        "Module":"ContainerSecurity",
        "Category":"ATT&CK"
    },
    "NotifyContext":{
        "Namespace": .output_fields."k8s.ns.name",
        "PodName": .output_fields."k8s.pod.name",
        "Cluster": "default",
        "CustomKV": [
        {
          "KVHash":{
              "en":{
                  "Key": "containerId",
                  "Value": .output_fields."container.id"
              },
              "zh":{
                  "Key":"容器id",
                  "Value": .output_fields."container.id"
              }
          }
       },
       {
          "KVHash":{
              "en":{
                  "Key": "syscall",
                  "Value": .output_fields."syscall.type"
              },
              "zh":{
                  "Key":"系统调用",
                  "Value": .output_fields."syscall.type"
              }
          }
       },
        {
          "KVHash":{
              "en":{
                  "Key": "command",
                  "Value": .output_fields."proc.cmdline"
              },
              "zh":{
                  "Key":"命令",
                  "Value": .output_fields."proc.cmdline"
              }
          }
       },
       {
          "KVHash":{
              "en":{
                  "Key": "user",
                  "Value": .output_fields."user.name"
              },
              "zh":{
                  "Key":"用户",
                  "Value": .output_fields."user.name"
              }
          }
       }
      ]
    },
    "Timestamp":0,
    "UUID":0
}')

  rule=$(echo $req | jq -r '.RuleKey.Name')
  if [[ $rule == Falco* ]]; then
    echo "start with Falco, ignore it"
    return
  fi

  cur_timestamp=`date +%s`
  rand=`openssl rand -base64 32 | cksum | cut -c 1-8`
  uuid=$((($cur_timestamp << 32) | $rand))
  req=$(echo $req | jq ".Timestamp=${cur_timestamp}" | jq ".UUID=\"${uuid}\"")

  url=$EVENTCENTER_HTTP_URL
  if [[ -z $url ]]; then
    url=https://tensorsec-eventcenter:8080/eventcenter/sendNotification
  fi

  ca_path=$EVENTCENTER_CA_PATH
  if [[ -z $ca_path ]]; then
    ca_path=/auth/ca/tls.crt
  fi

  client_cert_path=$EVENTCENTER_CLIENT_CERT_PATH
  if [[ -z $client_cert_path ]]; then
    client_cert_path=/auth/client/tls.crt
  fi

  client_key_path=$EVENTCENTER_CLIENT_KEY_PATH
  if [[ -z $client_key_path ]]; then
    client_key_path=/auth/client/tls.key
  fi

  echo "url:" $url
  echo "req:" $req

  curl -d "${req}" $url --cert $client_cert_path --key $client_key_path --cacert $ca_path
}

alert
