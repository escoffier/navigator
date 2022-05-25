package audit

import (
	"bytes"
	"golang.org/x/net/context"
	"io"
)

const (
	POST   = "POST"
	PUT    = "PUT"
	DELETE = "DELETE"
)

var Request2Verb = map[string]map[string]string{
	//平台报告
	"/api/v2/platform/report/template": {POST: "新增平台报告", PUT: "编辑平台报告", DELETE: "删除平台报告 "},
	//主动防御
	"/api/v2/containerSec/watson/baitService": {PUT: "新增诱捕服务", POST: "编辑诱捕服务", DELETE: "删除诱捕服务"},
	//用户登录
	"/api/v2/usercenter/login": {POST: "登录"},
	//资产发现
	"/api/v2/platform/assets/namespace":         {POST: "编辑命名空间"},
	"/api/v2/platform/assets/resource/userData": {POST: "编辑资源"},
	//镜像安全
	"/api/v2/containerSec/scanner/scan-config/config/1": {PUT: "编辑扫描配置"},
	//"/api/v2/containerSec/scanner/scan-config/strategy":          {POST: "新增扫描策略", PUT: "编辑扫描策略", DELETE: "删除扫描策略"},
	"/api/v2/containerSec/scanner/scan-report":                   {POST: "新增镜像扫描报告", PUT: "编辑镜像扫描报告", DELETE: "删除镜像扫描报告"},
	"/api/v2/containerSec/scanner/register/registry":             {POST: "新增镜像仓库", PUT: "编辑镜像仓库", DELETE: "删除镜像仓库"},
	"/api/v2/containerSec/scanner/images/bases":                  {POST: "新增基础镜像+镜像名称至基础镜像列表", DELETE: "删除基础镜像+镜像名称出基础镜像列表"},
	"/api/v2/containerSec/scanner/imagereject/trustedImages/rsa": {POST: "新增密钥", PUT: "编辑密钥", DELETE: "删除密钥"},
	"/api/v2/containerSec/scanner/scanone":                       {POST: "新增镜像扫描任务"},
	"/api/v2/containerSec/scanner/imagereject/whitelist":         {POST: "新增镜像 + 镜像名至阻断白名单", DELETE: "删除镜像 + 镜像名出阻断白名单"},
	"/api/v2/containerSec/scanner/imagereject/policy/global":     {PUT: "编辑阻断节点配置"},
	"/api/v2/containerSec/scanner/imagereject/policy/single":     {POST: "新增阻断策略", PUT: "编辑阻断策略", DELETE: "删除阻断策略"},
}

// limitBuffer is used to pipe response body information from the
// response writer to a certain limit amount. The idea is to read
// a portion of the response body such as an error response so we
// may log it.
type limitBuffer struct {
	*bytes.Buffer
	limit int
}

type Metadata struct {
	ObjectName string
	CustomKV   map[string]interface{}
}

func metadataFromContext(ctx context.Context) (*Metadata, bool) {
	meta, ok := ctx.Value("metadata").(*Metadata)
	return meta, ok
}
func newLimitBuffer(size int) io.ReadWriter {
	return limitBuffer{
		Buffer: bytes.NewBuffer(make([]byte, 0, size)),
		limit:  size,
	}
}

func (b limitBuffer) Write(p []byte) (n int, err error) {
	if b.Buffer.Len() >= b.limit {
		return len(p), nil
	}
	limit := b.limit
	if len(p) < limit {
		limit = len(p)
	}
	return b.Buffer.Write(p[:limit])
}

func (b limitBuffer) Read(p []byte) (n int, err error) {
	return b.Buffer.Read(p)
}
