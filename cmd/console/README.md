日志输出参数： 
```
--log-output-file bool    是否输出日志到文件
--log-close-console bool  需要log-output-file选项启用. 是否输出到控制台，如果没有启用输出到文件，这个设置无效 
--log-filename string     需要log-output-file选项启用. 日志文件输出路径 (default "/var/log/console.log")
--log-max-age int         需要log-output-file选项启用. 日志文件最大存在时间 (default 30)
--log-max-backups int     需要log-output-file选项启用. 日志文件最大数量 (default 30)
--log-max-size int        需要log-output-file选项启用. 日志文件允许最大是多少. 单位MB (default 100)
--log-rotate-time string  需要log-output-file选项启用. 支持(@hourly=每小时 @daily=每天 @weekly=每周 @monthly=每月) (default "@daily")

TraceLevel = -1
DebugLevel = 0
InfoLevel = 1
WarnLevel = 2
ErrorLevel = 3
FatalLevel = 4
PanicLevel = 5
NoLevel = 6
Disabled = 7
--log-level int           日志输出等级。 默认0 
```