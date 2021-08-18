# webshell-server
一个接收http请求，并对http请求中的文件内容做webshell检测的web服务。

## background
由于 [cloudwalker ](https://github.com/chaitin/cloudwalker) 无法支持并发检测，因此把检测webshell逻辑抽离出一个独立的服务，通过部署多个服务实例达到并发检测的效果。

## support

- [x] php
- [ ] other

## run