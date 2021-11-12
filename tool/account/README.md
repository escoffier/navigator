## 账户模块工具
账户模块小脚本
- 查看帮助: ./account-tool -h
- 编译脚本: ./build.sh
### 添加用户
- 查看帮助: ./account-tool addUser -h
- 示例
```
   添加一个普通用户 用户名为test1 密码为test1 没有任何模块的写权限
  ./account-tool addUser --pgDSN="xxx" --username=test1 --password=test1 --role=normal
```
```
    添加一个普通用户 用户名为test1 密码为test1 拥有模块id为2和3模块写权限
  ./account-tool addUser --pgDSN="xxx" --username=test1 --password=test1 --role=normal --moduleID=2 --moduleID=3

```
```
    添加一个管理员 用户名为test2 密码为test2 拥有模块id为2和3模块写权限
  - ./account-tool addUser --pgDSN="xxx" --username=test2 --password=test2 --role=admin --moduleID=2 --moduleID=3
```

```
    添加一个超级管理员 用户名为test3 密码为test3 拥有模块id为2和3模块写权限
  - ./account-tool addUser --pgDSN="xxx" --username=test2 --password=test2 --role=admin --moduleID=2 --moduleID=3
```

### 查看平台所有模块信息
```
./account-tool showModules

```