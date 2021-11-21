## 免疫防御测试
用curl 直接访问http服务器即可 GET请求
### apparmor
route:/apparmor 
### commandWhiteList
route:/commandWhiteList
### driftPrevention
route: /driftPrevention
### seccomp
route: /seccomp

### 示例
- curl http://172.21.1.191:32687/apparmor
- curl http://172.21.1.191:32687/commandWhiteList
- curl http://172.21.1.191:32687/driftPrevention
- curl http://172.21.1.191:32687/seccomp