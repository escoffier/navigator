#!/bin/bash

#$1 library $2 namespace $3 imagename $4 tag $5 max_second $6 console连接 $7 console用户名 $8 console密码 $9 仓库帐号 $10 仓库密码

# such sh -x test-run.sh registry.t-appagile.com docker_contenttrust myshop v2 300 https://console3-test-cn.tensorsecurity.cn username password

#image=registry.t-appagile.com/cicd-test/test:v1

image=$1"/"$2"/"$3":"$4 #域名+full_repo_name+tag

full_repo_name=$2"/"$3
echo ${image}

mingling="sed -nr \'s#.*token\":\"(.*)\",.*#\1#p\'"

token=`curl -H "Content-Type: application/json" -X POST -d "{\"username\": \"${7}\", \"password\": \"${8}\"}" "${6}/api/v2/usercenter/login" -k -m 30 --connect-timeout 5 --retry 5| sed -nr 's#.*token\":\"(.*)\",.*#\1#p'`

echo ${token}

json="{\"library\":\"${1}\",\"full_repo_name\":\"${full_repo_name}\",\"tag\":\"${4}\",\"max_second\":\"${5}\"}"


docker login -u$9 -p$10 $1

docker push $image

# create project

# scan request


resjson=`curl -H "Content-Type: application/json" -H "authorization: Bearer ${token}" -X POST -d ${json} "${6}/api/v2/containerSec/scanner/imagereject/scanone/cicd" -m 300`

echo ${resjson}

IsExit=$(echo $resjson | grep "false")

if [[ "${IsExit}" != "" ]]
then
	exit 2
fi

# query result
