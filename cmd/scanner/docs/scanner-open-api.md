# openapi 文档

## Base URL

本产品属于一款本地部署产品，Base URL 自主设置。示例: [ https://console-test-cn.tensorsecurity.cn]()

## 统一错误返回

除特别说明之外，所有的url请求出错后，返回的数据格式如下

```json
{
  "apiVersion": "1.0",
  "error": {
	"code": 601,
	"message": "查询镜像出错"
  }
}
```

### 返回数据说明

- ```apiVersion``` apiVersion
- ```error``` 出错信息
    - ```code``` 程序定义的错误码
    - ```message``` 简明的错误信息

前端通过HTTP code 判断此次请求是否成功

## 统一HTTP状态码

除特别说明之外，所有的url请求返回状态码含义如下

| 状态码 | 说明 |
| --- | --- |
| 200 | 同步请求成功 |
| 201 | 异步请求成功 |
| 401 | 未经授权 |
| 403 | 无权访问该项资源 |
| 404 | 未找到请求路径 |
| 408 | 请求超时 |
| 410 | 未查询到对应的资源 |
| 429 | 超过请求频率 |
| 500 | 服务器内部错误 |

## 请求频率

除特别说明外，所有api默认请求频率限制：20次/秒

## 镜像扫描相关接口

### 获取镜像列表

获取镜像列表

| 调用URL            | 调用方法 |
| ------------------ | -------- |
| [/openapi/scanner/images]() | GET      |

#### 请求参数

| 是否必填 | 参数名       | 参数类型 | 参数位置 | 参数说明                                                     |
| -------- | ------------ | -------- | -------- | ------------------------------------------------------------ |
| 否       | limit        | Int      | Query    | 列表返回条数限制，默认10，最大100                                             |
| 否       | offset       | Int      | Query    | 从第几条开始，分页使用，默认0                                       |
| 否       | online       | String   | Query    | 在线或离线筛选，在线:true,离线:false                     |
| 否       | search       | String   | Query    | 关键词搜索,搜索范围是镜像名                                                   |
| 否       | securityIssue         | String   | Query    | 安全问题搜索，以```","```拼接, 0:漏洞,1:病毒，2:敏感文件,3:webshell文件，4:异常软件，5:异常环境变量，6:特权启动 7:异常开源协议,注意：取交集 |
| 是       | fromType     | string      | Query    | 来源镜像筛选，registry:仓库镜像，node:节点镜像                         |
| 否       | scanStatus   | String   | Query    | 扫描状态搜索，以```","```拼接, 1:等待中,2:扫描中,3:扫描成功,4:扫描失败, 5:未扫描。取并集 |
| 否       | imageType    | String   | Query    | 镜像类型筛选，1:基础镜像，0:应用镜像                     |
| 否       | trusted      | String   | Query    | 可信镜像筛选，1:表示可d信镜像，0:表示非可信镜像          |
| 否       | reinforced  | String   | Query    | 是否加固镜像筛选，1:表示已加固镜像，0:表示未加固镜像     |
| 否       | hasFixedVuln | String   | Query    | 存在可修复漏洞镜像筛选，"1":表示存在可修复漏洞镜像，"0":表示不存在可修复漏洞镜像 |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "items": [
            {
                "lastScanedAt": 1638995855012,
                "digest": "sha256:94b0a7814c76e7eb32e9764fd42b29a7384e180cfe0a4dc1bd8d1b8d3070b10d",
                "fromType": "node",
                "image": "https://harbor.tensorsecurity.com/app-image/app-base-alpine:v1",
                "hasFixedVuln": 1,
                "imageType": 0,
                "reinforced": 0,
                "nodeHostname": "",
                "nodeIp": "",
                "online": false,
                "securityIssue":[0,1],
                "registryName": "test",
                "riskScore": 45,
                "scanStatus": 3,
                "trusted": 0
            }
        ],
        "itemsPerPage": 1,
        "startIndex": 0,
        "totalItems": 1432
    }
}
```

#### 返回值说明

- ```lastScanedAt``` 最后一次扫描时间的时间戳
- ```digest``` 镜像digest签名
- ```fromType``` 镜像来源，registry:仓库镜像，node:节点镜像
- ```image``` 完整镜像名
- ```hasFixedVuln``` 是否存在可修复漏洞，1：存在，0：不存在
- ```imageType``` 镜像类型，1：基础镜像，0：应用镜像
- ```reinforced``` 镜像是否已加固，1：已加固，0：未加固
- ```nodeHostname``` 节点镜像的节点名称
- ```nodeIp``` 节点镜像的节点IP
- ```online``` 镜像是否在线,true:在线，false：离线
- ```securityIssue``` 问题列表，0:包含漏洞,1:包含病毒，2:包含敏感文件,3:包含webshell文件，4:包含异常软件，5:包含异常环境变量，6:属于特权启动 7:异包含常开源协议
- ```registryName``` 镜像所在的仓库名
- ```riskScore``` 镜像评分
- ```scanStatus``` 镜像最近一次扫描状态，1:等待中,2:扫描中,3:扫描成功,4:扫描失败, 5:未扫描
- ```trusted``` 是否属于可信镜像，1：可信，0：不可信
- ```itemsPerPage``` 列表返回条数限制
- ```startIndex``` 当前页数
- ```totalItems``` 查询的总数

### 镜像概况统计信息

获取镜像概况统计

| 调用URL                              | 调用方法 |
| ------------------------------------ | -------- |
| [/openapi/scanner/statistic/images]() | GET      |

#### 请求参数

| 是否必填 | 参数名   | 参数类型 | 参数位置 | 参数说明                             |
| -------- | -------- | -------- | -------- | ------------------------------------ |
| 是       | fromType | String      | Query    | 来源镜像筛选，registry:仓库镜像，node:节点镜像  |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "item": {
            "imageTotal": 1432,
            "online": {
                "exceptEnvs": 0,
                "notAllowedLicense": 0,
                "privilegedBoot": 30,
                "sensitiveFile": 43,
                "nonCompliantSoftware": 0,
                "virus": 43,
                "vulns": 27,
                "webshell": 43
            },
            "onlineTotal": 43,
            "total": {
                "exceptEnvs": 0,
                "notAllowedLicense": 0,
                "privilegedBoot": 1361,
                "sensitiveFile": 1398,
                "nonCompliantSoftware": 0,
                "virus": 1202,
                "vulns": 1215,
                "webshell": 1203
            }
        },
    }
}
```

#### 返回值说明

- ```imageTotal``` 镜像总数
- ```onlineTotal``` 在线镜像总数
- ```online``` 在线镜像统计信息
    - ```exceptEnvs```:存在异常环境变量的镜像数
    - ```notAllowedLicense``` 存在不允许的开源许可的镜像数
    - ```privilegedBoot``` 存在特权启动的镜像数
    - ```sensitiveFile``` 存在敏感文件的镜像数
    - ```nonCompliantSoftware``` 存在不合规软件的镜像数
    - ```virus``` 存在病毒文件的镜像数
    - ```vulns``` 存在漏洞的镜像数
    - ```webshell``` 存在WebShell的镜像数
- ```total``` 总的镜像统计信息
    - ```exceptEnvs```:存在异常环境变量的镜像数
    - ```notAllowedLicense``` 存在不允许的开源许可的镜像数
    - ```privilegedBoot``` 存在特权启动的镜像数
    - ```sensitiveFile``` 存在敏感文件的镜像数
    - ```nonCompliantSoftware``` 存在不合规软件的镜像数
    - ```virus``` 存在病毒文件的镜像数
    - ```vulns``` 存在漏洞的镜像数
    - ```webshell``` 存在WebShell的镜像数

### 获取特定镜像详情

获取特定镜像的详情

| 调用URL                                                      | 调用方法 |
| ------------------------------------------------------------ | -------- |
| [ /openapi/scanner/registries/:registryName/images/:imageName ]() | GET      |

#### 请求参数

| 是否必填 | 参数名       | 参数类型 | 参数位置 | 参数说明 |
| -------- | ------------ | -------- | -------- | -------- |
| 是       | registryName | String   | Path     | 仓库名   |
| 是       | imageName    | String   | Path     | 镜像名   |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "item": {
            "digest": "sha256:94119e29d9e80cf4bcbc2a7d2d1eb8697cb2531b3f0a06dc65f1883ebdcd40b1",
            "fromType": "node",
            "image": "https://harbor.tensorsecurity.com/app-image/app-base-alpine:v1",
            "sensitiveFile": [
                "id_rsa"
            ],
            "virus": [
                {
                    "filename": "acb930a41abdc4b055e2e3806aad85068be8d85e0e0610be35e784bfd7cf5b0e",
                    "filepath": "/Linux.Mirai.B/",
                    "virusname": " Unix.Malware.Agent-9157836-0"
                }
            ],
            "envs": [
                {
                    "envName": "PATH",
                    "envValue": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "isAbnormal": 0
                }
            ],
            "webshell": [
                {
                    "codes": [
                        "assert')&&($b = $_POST"
                    ],
                    "filename": "cmd1.jsp",
                    "filepath": "Language_type/",
                    "score": 10
                }
            ],
            "vulns": [
                {
                    "name": "漏洞编号",
                    "severity": "严重程度",
                    "fixedVersion": "修复版本",
                    "desription": "漏洞介绍",
                    "fixSuggestion": "修复建议",
                    "references": [
                        "参考链接"
                    ],
                    "title": "漏洞类型",
                    "score": 10,
                    "pkgname": "软件包",
                    "pkgversion": "软件版本",
                    "cvss": {
                        "score": "9.800000",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                }
            ],
            "imageType": 0,
            "reinforced": 0,
            "nodeHostname": "",
            "nodeIp": "",
            "privilegedBoot": 1,
            "size": 39709733,
        }
    }
}
```

#### 返回值说明

- ```digest``` 镜像digest签名
- ```fromType``` 镜像来源，registry：仓库镜像，node：节点镜像
- ```image``` 镜像名
- ```sensitiveFile```  敏感文件集合
- ```virus``` 病毒信息
    - ```filename``` 病毒文件名
    - ```filepath``` 病毒文件路径
    - ```virusname```  病毒名
- ```envs``` 环境变量信息
    - ```envName``` 环境变量名
    - ```envValue```  环境变量值
    - ```isAbnormal``` 是否异常，1表示异常，0表示正常
- ```webshell``` web shell 文件信息
    - ```codes``` web shell 执行的代码
    - ```filename``` web shell 文件名
    - ```filepath``` web shell 文件路径
    - ```score``` web shell 评分
- ```vulns``` 漏洞信息
    - ```name```  漏洞名
    - ```severity```  严重等级
    - ```fixedVersion```  修复版本
    - ```desription```  漏洞介绍
    - ```fixSuggestion``` 修复建议
    - ```references``` 参考链接
    - ```title```漏洞类型
    - ```score``` 漏洞评分
    - ```pkgname``` 软件包
    - ```pkgversion``` 软件版本
    - ```cvss``` cvss系统评分
- ```imageType``` 镜像类型，1：基础镜像，0：应用镜像
- ```reinforced``` 镜像是否已加固，1：已加固，0：未加固
- ```nodeHostname``` 节点镜像所在节点的节点名
- ```nodeIp``` 节点镜像所在节点的节点IP
- ```privilegedBoot``` 镜像是否是特权启动：1：特权启动，0：非特权启动
- ```size```  镜像大小，单位kb

### 镜像回溯信息

获取特定仓库下特定镜像的各层级信息

| 调用URL | 调用方法 |
| --- | --- |
| [/openapi/scanner/registries/:registryName/images/:imageName/layers]() | GET |

#### 请求参数

|  是否必填  | 参数名 | 参数类型 | 参数位置 | 参数说明 |
| --- | --- | --- | --- | --- |
|  是 | registryName  | String| Path | 仓库名|
|  是 |  imageName | String | Path | 镜像名|

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "items": [
            {
                "createdAt": 1638995855012,
                "createdBy": "/bin/sh -c #(nop)",
                "digest": "sha256:25fa05cd42bd8fabb25d2a6f3f8c9f7ab34637903d00fd2ed1c1d0fa980427dd",
                "virus": [
                    "Unix.Malware.Agent-6324931-0"
                ],
                "sensitiveFile": [
                    "xxx.sql"
                ],
                "vulns": [
                    "CNNVD-201703-077"
                ],
                "webshell": [
                    "system.php"
                ],
                "exceptEnvs": [
                    "PATH"
                ]
            }
        ]
    }
}
```

#### 返回值说明

- ```createdAt``` 该层级创建时间的时间戳
- ```createdBy``` 创建命令
- ```digest``` 该层的digest签名
- ```virus``` 病毒名集合
- ```sensitiveFile``` 敏感文件名集合
- ```vulns``` 漏洞名集合
- ```webshell``` web shell 文件名集合
- ```exceptEnvs``` 异常环境变量名集合

### 创建扫描任务

根据传入的条件，对筛选的镜像创建扫描任务

| 调用URL | 调用方法 |
| --- | --- |
| [openapi/scanner/scan/scantask]() | POST |

#### 请求参数

```json
{
  "online": "false",
  "search": "hello",
  "securityIssue": "0,1,2,3,4,5,6,7",
  "fromType": "node",
  "imageType": "1",
  "trusted": "1",
  "hasFixedVuln": "1",
  "reinforced": "1",
  "strategyName": "默认扫描策略",
  "operator": "admiin@163.cn"
}
```

|  是否必填  | 参数名 | 参数类型 | 参数位置 | 参数说明 |
| --- | --- | --- | --- | --- |
|  否 | online  | String| Body | 在线或离线筛选，在线:"true",离线:"false"|
|  否 | search | String | Body | 关键词搜索|
|  否 | securityIssue | String | Body | 安全问题搜索，以```","```拼接, 0:漏洞,1:病毒，2:敏感文件,3:webshell文件，4:异常软件，5:异常环境变量，6:特权启动 7:异常开源协议,注意：安全问题筛选是取交集|
|  是 |  fromType | String | Body | 来源镜像筛选，registry:仓库镜像，node:节点镜像 |
|  否 |  imageType | String | Body | 镜像类型涮选，1:基础镜像，0:应用镜像 |
|  否 |  trusted | String | Body | 可信镜像筛选，1:表示可信镜像，0:表示非可信镜像 |
|  否 |  reinforced | String | Body | 是否加固镜像筛选，1:表示已加固镜像，0:表示未加固镜像 |
|  否 |  hasFixedVuln | String | Body | 存在可修复漏洞镜像筛选，1:表示存在可修复漏洞镜像，0:表示不存在可修复漏洞镜像 |
|  是 |  strategyName | String | Body | 扫描使用的策略 |
|  是 |  operator | String | Body | 创建此次扫描任务的操作人 |

#### 请求成功返回数据

``` json 
{
    "apiVersion": "1.0",
    "data": {
    }
}
```

#### 返回值说明

http code 200表示创建成功

### 扫描策略列表

扫描策略列表

| 调用URL                                    | 调用方法 |
| ------------------------------------------ | -------- |
| [openapi/scanner/scan-config/strategies]() | GET      |

#### 请求参数

| 是否必填 | 参数名 | 参数类型 | 参数位置 | 参数说明               |
| -------- | ------ | -------- | -------- | ---------------------- |
| 否       | limit  | Int      | Query    | 列表返回条数限制，默认10，最大100       |
| 否       | offset | Int      | Query    | 从第几条开始，分页使用，默认0 |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "items": [
            {
                "id": 3,
                "name": "扫描策略1",
                "describe": "扫描策略1",
                "sensitiveFile": [
                    {
                        "value": ".sql"
                    }
                ],
                "exceptEnvs": [
                    "PATH"
                ],
                "notAllowedLicense": [
                    "BSD"
                ],
                "nonComplianceSoftware": [
                    {
                        "name": "lib/hello",
                        "version": "v2"
                    }
                ],
                "operator": "admiin@163.cn"
            }
        ],
        "itemsPerPage": 1,
        "startIndex": 0,
        "totalItems": 139349
    }
}
```

#### 返回值说明

- ```name``` 策略名
- ```describe``` 策略描述
- ```sensitiveFile``` 自定义敏感文件
    - ```value``` 自定义敏感文件的正则表达式
- ```exceptEnvs``` 自定义异常环境变量的KEY
- ```notAllowedLicense``` 不允许的开源协议，可选项：BSD,Apache License,MPL,MIT,"GPL"
- ```nonComplianceSoftware``` 自定义不合规软件
    - ```name``` 软件名
    - ```version``` 软件版本
- ```operator``` 操作人
- ```itemsPerPage``` 列表返回条数限制
- ```startIndex``` 当前页数
- ```totalItems``` 查询的总数

### 扫描策略详情

获取扫描策略详情

| 调用URL                                                  | 调用方法 |
| -------------------------------------------------------- | -------- |
| [openapi/scanner/scan-config/strategies/:strategyName]() | GET      |

#### 请求参数

| 是否必填 | 参数名       | 参数类型 | 参数位置 | 参数说明     |
| -------- | ------------ | -------- | -------- | ------------ |
| 是       | strategyName | String   | Path     | 扫描策略名字 |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "item": {
            "id": 3,
            "name": "扫描策略1",
            "describe": "扫描策略1",
            "sensitiveFile": [
                {
                    "value": ".sql"
                }
            ],
            "exceptEnvs": [
                "PATH"
            ],
            "notAllowedLicense": [
                "BSD"
            ],
            "nonComplianceSoftware": [
                {
                    "name": "lib/hello",
                    "version": "v2"
                }
            ],
            "operator": "admiin@163.cn"
        }
    }
}
```

#### 返回值说明

- ```name``` 策略名
- ```describe``` 策略描述
- ```sensitiveFile``` 自定义敏感文件
    - ```value``` 自定义敏感文件的正则表达式
- ```exceptEnvs``` 自定义环境变量的KEY
- ```notAllowedLicense``` 不允许的开源协议，可选项：BSD,Apache License,MPL,MIT,GPL
- ```nonComplianceSoftware``` 自定义不合规软件
    - ```name``` 软件名
    - ```version``` 软件版本
- ```operator``` 操作人

### 创建扫描策略

创建镜像扫描策略

| 调用URL | 调用方法 |
| --- | --- |
| [openapi/scanner/scan-config/strategies]() | POST |

#### 请求参数

body传参

```json
{
  "name": "扫描策略1",
  "describe": "扫描全部",
  "sensitiveFile": [
	{
	  "value": ".sql"
	}
  ],
  "exceptEnvs": [
	"PATH"
  ],
  "notAllowedLicense": [
	"BSD"
  ],
  "nonComplianceSoftware": [
	{
	  "name": "lib/hello",
	  "version": "v2"
	}
  ],
  "operator": "admiin@163.cn"
}

```

#### 参数说明

- ```name``` 策略名
- ```describe``` 策略描述
- ```sensitiveFile``` 自定义敏感文件
    - ```value``` 自定义敏感文件的正则表达式
- ```exceptEnvs``` 自定义环境变量的KEY
- ```notAllowedLicense``` 不允许的开源协议，可选项：BSD,Apache License,MPL,MIT,GPL
- ```nonComplianceSoftware``` 自定义不合规软件
    - ```name``` 软件名
    - ```version``` 软件版本
- ```operator``` 操作人

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "item": {
            "id": 3,
        }
    }
}
```

#### 返回数据说明

- ```id``` 数据ID

### 更新扫描策略

全量更新扫描策略

| 调用URL | 调用方法 |
| --- | --- |
| [openapi/scanner/scan-config/strategies/:strategyName]() | PUT |

#### 请求参数

|  是否必填  | 参数名 | 参数类型 | 参数位置 | 参数说明 |
| --- | --- | --- | --- | --- |
|  是 | strategyName  | String| Path | 策略名 |

body传参

```json
{
  "name": "扫描策略1",
  "describe": "扫描策略1",
  "sensitiveFile": [
	{
	  "value": ".sql"
	}
  ],
  "exceptEnvs": [
	"PATH"
  ],
  "notAllowedLicense": [
	"BSD"
  ],
  "nonComplianceSoftware": [
	{
	  "name": "lib/hello",
	  "version": "v2"
	}
  ],
  "operator": "admiin@163.cn"
}

```

body参数说明

- ```name``` 策略名
- ```describe``` 策略描述
- ```sensitiveFile``` 自定义敏感文件
    - ```value``` 自定义敏感文件的正则表达式
- ```exceptEnvs``` 自定义环境变量的KEY
- ```notAllowedLicense``` 不允许的开源协议，可选项：BSD,Apache License,MPL,MIT,"GPL"
- ```nonComplianceSoftware``` 自定义不合规软件
    - ```name``` 软件名
    - ```version``` 软件版本
- ```operator``` 操作人

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
    }
}
```

#### 返回值说明

无返回值，根据http code判断是否更新成功

#### 请求失败返回数据

### 删除扫描策略

删除扫描策略

| 调用URL | 调用方法 | 
| --- | --- |
| [openapi/scan-config/strategies/:strategyName]() | DELETE |

#### 请求参数

|  是否必填  | 参数名 | 参数类型 | 参数位置 | 参数说明 |
| --- | --- | --- | --- | --- |
|  是 | strategyName | String | Path | 扫描策略名字|              

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
    }
}
```

#### 返回值说明

无返回值，根据http code判断是否删除成功

## 漏洞发现相关接口

### 获取漏洞列表

获取漏洞列表,按严重级别排序

| 调用URL                    | 调用方法 |
| -------------------------- | -------- |
| /[openapi/scanner/vulns]() | GET      |

#### 请求参数

| 是否必填 | 参数名 | 参数类型 | 参数位置 | 参数说明               |
| -------- | ------ | -------- | -------- | ---------------------- |
| 否       | limit  | Int      | Query    | 列表返回条数限制，默认10，最大100 |
| 否       | offset | Int      | Query    | 从第几条开始，分页使用，默认0 |
| 否       | search | String   | Query    | 关键词搜索   |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "items": [
            {
                "name": "漏洞编号",
                "severity": "严重程度",
                "fixedVersion": "修复版本",
                "desription": "漏洞介绍",
                "fixSuggestion": "修复建议",
                "references": [
                    "参考链接"
                ],
                "title": "漏洞类型",
                "score": 10,
                "pkgname": "软件包",
                "pkgversion": "软件版本",
                "cvss": {
                        "score": "9.800000",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
            }
        ],
        "itemsPerPage": 10,
        "startIndex": 0,
        "totalItems": 139349
    }
}
```

#### 返回值说明

- ```name```  漏洞名
- ```severity```  严重等级
- ```fixedVersion``` 修复版本
- ```desription```  漏洞介绍
- ```fixSuggestion``` 修复建议
- ```references``` 参考链接
- ```title```漏洞类型
- ```score``` 漏洞评分
- ```pkgname``` 软件包
- ```pkgversion``` 软件版本
- ```cvss``` cvss系统评分
- ```itemsPerPage``` 列表返回条数限制
- ```startIndex``` 当前页
- ```totalItems``` 总数

### 获取特定漏洞详情

获取特定漏洞详情

| 调用URL | 调用方法 |
| --- | --- |
| [/openapi/scanner/vulns/:vulnName]() | GET |

#### 请求参数

|  是否必填  | 参数名 | 参数类型 | 参数位置 | 参数说明 |
| --- | --- | --- | --- | --- |
|  是 | vulnName  | String| Path | 漏洞名 |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "item": {
            "name": "漏洞编号",
            "severity": "严重程度",
            "fixedVersion": "修复版本",
            "desription": "漏洞介绍",
            "fixSuggestion": "修复建议",
            "references": [
                "参考链接"
            ],
            "title": "漏洞类型",
            "score": 10,
            "pkgname": "软件包",
            "pkgversion": "软件版本",
            "cvss": {
                "score": "9.800000",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        }
    }
}
```

#### 返回值说明

- ```name```  漏洞名
- ```severity```  严重等级
- ```fixedVersion``` 修复版本
- ```desription```  漏洞介绍
- ```fixSuggestion``` 修复建议
- ```references``` 参考链接
- ```title```漏洞类型
- ```score``` 漏洞评分
- ```pkgname``` 软件包
- ```pkgversion``` 软件版本
- ```cvss``` cvss系统评分

### 漏洞统计

漏洞统计

| 调用URL | 调用方法 |
| --- | --- |
| [/openapi/scanner/statistic/vulns]() | GET |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "item": {
            "severity": {
                "critical": 9956,
                "high": 37373,
                "low": 25017,
                "medium": 66396,
                "negligible": 0,
                "unknown": 607
            },
            "top5": [
                {
                    "image": "library/percona-mysql",
                    "score": 50,
                    "severity": {
                        "critical": 9956,
                        "high": 37373,
                        "low": 25017,
                        "medium": 66396,
                        "negligible": 0,
                        "unknown": 607
                    }
                }
            ],
            "vulnTotal": 139349
        }
    }
}
```

#### 返回值说明

- ```severity```  漏洞统计信息
    - ```critical``` 高危漏洞数
    - ```medium```  中风险漏洞数
    - ```high```  高风险漏洞数
    - ```low```  低风险漏洞数
    - ```negligible```  可忽略漏洞数
    - ```unknown```  未知风险漏洞

- ```top5``` 含有漏洞数量最我的5个镜像
    - ```image``` 镜像名
    - ```score``` 漏洞评分
    - ```severity```  该镜像的漏洞统计信息
        - ```critical``` 高危漏洞数
        - ```medium```  中风险漏洞数
        - ```high```  高风险漏洞数
        - ```low```  低风险漏洞数
        - ```negligible```  可忽略漏洞数
        - ```unknown```  未知风险漏洞
- ```vulnTotal``` 漏洞总数

## 合规检测相关接口

### 创建合规检测任务

| 调用URL | 调用方法 |
| --- | --- |
| [/openapi/scap/scan/scantask]() | POST |

body传参

```json
{
  "operator": "admiin@163.cn",
  "checkType": "docker",
  "clusterName": "12323232"
}
```

#### 请求参数

|  是否必填  | 参数名 | 参数类型 | 参数位置 | 参数说明 |
| --- | --- | --- | --- | --- |
|  是 | checkType  | String| Body | 检测类型，docker:表示检测Docker，host:表示检测主机，kube：表示检测kubernetes |
|  是 | clusterName  | String| Body | 集群名 |
|  是 | operator  | String| Body | 操作人 |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "item": {
            "checkUUID": "51450d4a-673c-4c85-a60c-ed110ef52312",
        },
    }
}
```

#### 返回值说明

- ```checkUUID```  本次检测任务的UUID

### 获取合规检测结果列表

| 调用URL | 调用方法 |
| --- | --- |
| [/openapi/scap/scan/record]() | GET |

#### 请求参数

| 是否必填 | 参数名       | 参数类型 | 参数位置 | 参数说明                                                     |
| --- | --- | --- | --- | --- |
| 否 | limit | Int | Query| 列表返回条数限制，默认10，最大100 |
| 否 | offset | Int | Query| 从第几条开始，分页使用，默认0|
| 是 | checkType  | String| Query | 检测类型，docker:表示检测Docker,host:表示检测主机，kube：表示检测kubernetes |
| 是 | clusterName  | String| Query | 集群名 |

#### 请求成功返回数据

``` json
{
    "apiVersion": "1.0",
    "data": {
        "items": [
            {
                "checkUUID": "51450d4a-673c-4c85-a60c-ed110ef52312",
                "classified": "资源控制",
                "description": "确保已将HEALTHCHECK指令添加到容器映像中,\n",
                "section": "容器镜像和构建文件\n",
                "numFailed": 5,
                "numInfo": 0,
                "numSuccessful": 0,
                "policyNumber": "4.6"
            }
        ]
    },
    "itemsPerPage": 10,
    "startIndex": 1,
    "totalItems": 100
}
```

#### 返回值说明

- ```checkUUID```  检测任务UUID
- ```policyNumber``` 合规ID
- ```classified``` 等保对齐
- ```section``` 合规条目
- ```description``` 具体要求
- ```itemsPerPage``` 列表返回条数限制
- ```startIndex``` 当前页
- ```totalItems``` 总数

### 获取合规检测任务列表

| 调用URL | 调用方法 |
| --- | --- |
| [/openapi/scap/scan/task]() | GET |

#### 请求参数

| 是否必填 | 参数名       | 参数类型 | 参数位置 | 参数说明                                                     |
| --- | --- | --- | --- | --- |
| 否 | checkUUID | String | Query| 检测任务UUID,默认最后一次任务的检测结果 |
| 是 | checkType  | String| Query | 检测类型，docker:表示检测Docker,host:表示检测主机，kube：表示检测kubernetes |
| 是 | clusterName  | String| Query | 集群名 |

#### 请求成功返回数据

```json
 {
  "apiVersion": "1.0",
  "data": {
	"items": [
	  {
		"checkId": "fe491613-0d85-489e-a32d-4699a5091769",
		"checkType": "kube",
		"clusterId": "177432933",
		"clusterName": "default",
		"createdAt": 1639450146,
		"operator": "xujianbo@tensorsecurity.cn",
		"finishedAt": 1639450146
	  }
	],
	"itemsPerPage": 500,
	"startIndex": 0,
	"totalItems": 16
  }
}
```

#### 返回数据说明

- ```checkId``` 任务ID
- ```checkType``` 检测类型，docker:表示检测Docker,host:表示检测主机，kube：表示检测kubernetes
- ```clusterId``` 集群ID
- ```clusterName``` 集群名
- ```createdAt``` 创建时间
- ```operator``` 任务创建人
- ```finishedAt``` 任务完成时间,等于0时说明任务正在扫描中

### 获取合规检测详情

| 调用URL | 调用方法 |
| --- | --- |
| [/openapi/scap/scan/record/tasks/:taskID]() | GET |

#### 请求参数

| 是否必填 | 参数名       | 参数类型 | 参数位置 | 参数说明                                                     |
| --- | --- | --- | --- | --- |
| 是 | taskID | String | Path | 合规任务ID|
| 否 | checkId | String | Query | 检测任务的ID，默认最后一次检测任务ID |
| 是 | checkType  | String| Query | 检测类型，docker:表示检测Docker,host:表示检测主机，kube：表示检测kubernetes |
| 是 | clusterName  | String| Query | 集群名 |

#### 请求成功返回数据

```json
  {
  "apiVersion": "1.0",
  "data": {
	"item": {
	  "successOn": [
		{
		  "nodeName": "ecs-edu-node-0002",
		  "remediation": "这样的条目增加了root可能\n执行非特权用户提供的代码，\n以及潜在的恶意代码的风险.\n"
		}
	  ],
	  "failedOn": [
		{
		  "nodeName": "ecs-edu-node-0002",
		  "remediation": ""
		}
	  ],
	  "warnOn": [
		{
		  "nodeName": "ecs-edu-node-0002",
		  "remediation": ""
		}
	  ]
	}
  }
}

```

#### 返回值说明

- ```successOn``` 合规节点信息
    - ```nodeName``` 节点名
    - ```remediation``` 扫描结果解释
- ```failedOn``` 不合规节点信息
    - ```nodeName``` 节点名
    - ```remediation``` 扫描结果解释
- ```warnOn``` 含有警告的信息
    - ```nodeName``` 节点名
    - ```remediation``` 扫描结果解释
