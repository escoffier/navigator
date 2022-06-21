package export

import (
	"github.com/xuri/excelize/v2"
	"testing"
	"time"
)

func Test_writeExcelFile(t *testing.T) {
	type args struct {
		filenamePrefix string
		auditLogs      []*Resp
	}
	tests := []struct {
		name    string
		args    args
		want    *excelize.File
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{
				filenamePrefix: "test_1",
				auditLogs: []*Resp{
					&Resp{
						ID:        "12222",
						Time:      time.Now(),
						UserName:  "qunfengqiu",
						Ip:        "192.168.254.122",
						Operation: "编辑",
						Detail:    "编辑用户名",
					}, &Resp{
						ID:        "12223",
						Time:      time.Now(),
						UserName:  "robbie",
						Ip:        "1.1.1.1",
						Operation: "新增",
						Detail:    "新增策略",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			excelFile, err := writeExcelFile(tt.args.filenamePrefix, tt.args.auditLogs)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeExcelFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			excelFile.Save()
		})
	}
}

func TestTime(t *testing.T) {
	t1 := time.UnixMilli(1654826383461)
	t.Log(t1)
	t2 := time.UnixMilli(1654826383461).In(time.FixedZone("CST", 8*3600))
	t.Log(t2)
}
