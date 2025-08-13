我现在要部署 portal 项目，请给我一个完整的部署文档
一，前置部署
1：部署 codesec 项目，由开源网安的人部署
2：部署 sourceCheck 项目，由开源网安的人部署
3：部署领航项目： 由领航的人部署
二，portal  后端部署
1: 部署的namespace 和领航一致，默认是 tensorsec
2: 创建数据表：使用的sql 是 ../up.sql
    2.1: 和领航使用同一个库，默认在 ivan 库下
3: 修改codesec配置文件：../portal-config.yaml
    3.1：codesec在部署后会内置一个管理员用户，需要修改../portal-config.yaml中的codeSec.adminUser.email和codeSec.adminUser.password
    3.2：codesec在部署后会内置一个组织用户，需要修改../portal-config.yaml中的codeSec.orgUser.email和codeSec.orgUser.password
    3.3：codesec在部署后会内置一个团队用户，需要修改../portal-config.yaml中的codeSec.teamUser.email和codeSec.teamUser.password
    3.4: 修改 codesec 部署地址，可能是内网地址，也可能是外网地址
4:修改sourceCheck配置文件：../portal-config.yaml    
    4.1：sourceCheck在部署后会内置一个管理员用户，需要修改../portal-config.yaml中的sourceCheck.adminUser.email和sourceCheck.adminUser.password,sourceCheck.adminUser.user_uuid
    4.2：sourceCheck在部署后会内置一个组织用户，需要修改../portal-config.yaml中的sourceCheck.orgUser.email和sourceCheck.orgUser.password,sourceCheck.adminUser.user_uuid
    4.3: 修改 sourceCheck 部署地址，可能是内网地址，也可能是外网地址
5:  修改 console 后端增加传参
    - --vegeta-portal-host=portal-backend
    - --vegeta-portal-port=10800
    注意，这里的 host 和 port 和下面创建的 service 保持一致

6：创建 configmap: kubectl -n tensorsec create configmap portal-config --from-file=portal-config.yaml 使用的文件是../portal-config.yaml
6：创建 deployment和service 使用的文件是：../portal-backend.yaml
三，部署前端
1：创建 deployment和service 使用的文件是：../portal-frontend.yaml
2：创建 ingress 使用的文件是：../portal-nginx-config.yaml



要求：
1，文档的格式 markdown
2,文档尽量全及详细
3，部署文档是给外部人员部署的，所以尽量详细
