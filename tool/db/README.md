## 数据库工具
账户模块小脚本
- 查看帮助: ./db-tool -h
- 编译脚本: ./build.sh

### 初始化数据库表结构
- 查看帮助: ./db-tool InitTables -h
- 首先确保schema.go里面的sql为最新建表字符串
- 示例 ./db-tool InitTables --pgDSN="xxx"
