在线更新漏洞库
执行计划

获取远端 version
  - 使用 OBS 客户端读取对象键 version，以字符串形式获取文件内容。
  - 将内容反序列化为 VulnDBVersion（Trivy 的同名结构）。
    
比较版本决定是否更新
  - 否则比较：remote.compressDBVersion != DBUpdateSrv.CompressDBVersion → 需要更新。
  - 其他情况跳过本轮。
    
拉取 vuln.zip 并执行更新
  - 当需要更新时，直接从 OBS 获取固定对象键 vuln.zip（二进制字节）。
  - 构造 UpdateDbParam{Updater: SeedAdmin, DbType: trivy, Data: zipBytes, CheckVersion: true}。
  - 调用现有 DBUpdateSrv.UpdateVulnDb(ctx, param) 执行漏洞库更新。
  - 成功后将 DBUpdateSrv.CompressDBVersion = remote.compressDBVersion。
    
后台定时循环
  - 每 5 分钟执行上述流程（仅主集群）。
  - 网络/解析/更新失败仅记录日志，等待下一轮重试。
    
参数来源
  - 使用 CLI flags：
    huawei-secret-id= ""
    huawei-secret-key= ""
    huawei-endpoint="obs.cn-southwest-2.myhuaweicloud.com"
    huawei-vuln-bucket="tensor-vuln-db"
    
关键对象键
  - 版本文件：version  用来标识版本号，确认是否更新
  - 压缩包文件：vuln.zip，如果需要更新就拉取该文件