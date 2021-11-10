package notifyhandler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	handler *Handler
)

func initHandler() {
	handler = NewHandler(&def.EmailConf{
		Username: "console-robot@tensorsecurity.cn",
		Host:     "smtp.feishu.cn",
		Port:     465,
		Password: "r8UJgg7ejpSoDOAF",
		BaseURL:  "https://console2-test-cn.tensorsecurity.cn/",
	})
}

func TestNotify(t *testing.T) {
	initHandler()
	nowTime := time.Now()
	assert.Equal(t, nil, handler.Notify(context.TODO(), &model.ReportTaskTemplateMeta{
		ID:     1,
		Name:   "测试周报",
		Emails: `["weichangan@tensorsecurity.cn", "huangsiyu@tensorsecurity.cn"]`,
	}, util.GetMillisecondTimestampByTime(nowTime.Add(-time.Hour*24*7)),
		util.GetMillisecondTimestampByTime(nowTime)))
}
