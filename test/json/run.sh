#! /bin/bash

function alert() {


  read -r origin_str
  output=$(echo ${origin_str} | jq -r .output)
  pid=$(echo ${origin_str} | awk -F "proc_pid=" '{print $2}' | awk -F "," '{print $1}')
  ppid=$(echo ${origin_str} | awk -F "proc_ppid=" '{print $2}' | awk -F "," '{print $1}')
  proc_name=$(echo ${origin_str} | awk -F "proc_cmdline=" '{print $2}' | awk  -F "," '{print $1}' | awk '{print $1}')
  proc_pname=$(echo ${origin_str} | awk -F "proc_pname=" '{print $2}' | awk  -F "," '{print $1}')

  req=$( echo $origin_str | jq -r  '. | {
    "RuleKey":{
        "Name": .rule,
        "Module":"ContainerSecurity",
        "Category":"ATT&CK"
    },
    "NotifyContext":{
        "Namespace": .output_fields."k8s.ns.name",
        "PodName": .output_fields."k8s.pod.name",
        "PodUID": .output_fields."k8s.pod.id",
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
    url=https://eventcenter:8080/eventcenter/sendNotification
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

  append_str=""
  if [[ -n $pid ]]; then
    append_str="$append_str { \"KVHash\": { \"en\": { \"Key\": \"pid\", \"Value\": \"${pid}\" }  , \"zh\": { \"Key\": \"进程号\", \"Value\": \"${pid}\" } } }, "
  fi

  if [[ -n $ppid ]]; then
    append_str="$append_str { \"KVHash\": { \"en\": { \"Key\": \"ppid\", \"Value\": \"${ppid}\" } , \"zh\": { \"Key\": \"父进程号\", \"Value\": \"${ppid}\" } } }, "
  fi

  if [[ -n $proc_name ]]; then
    append_str="$append_str { \"KVHash\": { \"en\": { \"Key\": \"procName\", \"Value\": \"${proc_name}(${pid})\" } , \"zh\": { \"Key\": \"执行进程\", \"Value\": \"${proc_name}(${pid})\" } } }, "
  fi

  if [[ -n $proc_pname ]]; then
        append_str="$append_str { \"KVHash\": { \"en\": { \"Key\": \"procPname\", \"Value\": \"${proc_pname}(${ppid})\" } , \"zh\": { \"Key\": \"父进程\", \"Value\": \"${proc_pname}(${ppid})\" } } }, "
  fi


  req=$(echo $req | sed "s/\"CustomKV\":[ ]\[/&${append_str}/")

  # echo "url:" $url
  # echo $req

  curl -d "${req}" $url --cert $client_cert_path --key $client_key_path --cacert $ca_path
}

alert
