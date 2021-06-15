#tensor-migrate

## background
数据库作为重要的外部依赖项，并不需要自动创建，如果开发测试环境需要自动创建DB，应该在环境初始化脚本里完成。因此migration只负责升级指定DB.

## usage

### 创建新的migrate

```
./tensor-migrate -c config.yaml new "title"
```

- config.yaml
  db 配置
  ```
  database:
    dialect: postgres
    host: localhost
    port: 5432
    user: postgres
    password: password
	name: testdb
  ```
  
- title
  此次migrate的简要说明，体现在sql文件名里面。如:20210612110952_title.up.sql

创建完成后，会生成两个文件：
2021xxx_title.up.sql
2021xxx_title.down.sql

sql文件保存在 ./migration-versions文件夹里面。

### 执行migrate

```
./tensor-migrate -c config.yaml up
```

up操作会执行xxx.up.sql文件,同时db里面更新migrate记录

### 回退migrate

```
./tensor-migrate -c config.yaml down
```

down操作会执行xxx.down.sql文件,同时数据库里面会清除这次migrate的记录。


## db
默认使用tensor_migrattion表来记录migrate状态


 

  

