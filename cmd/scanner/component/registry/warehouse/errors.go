package warehouse

import (
	"errors"
)

var ErrAccessKeyOrAccessSecret = errors.New("AccessKey OR AccessSecret 信息有误")
var ErrNotConnectOrWrongUsernameOrPasswd = errors.New("不能连接到指定的仓库,请检查用户名或密码")
