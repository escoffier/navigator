package attck

import (
	"io/ioutil"
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/cryption"
)

func TestParseItems(t *testing.T) {
	data, err := ioutil.ReadFile("encrypt_rule.data")
	if err != nil {
		t.Fatal(err)
	}

	copyData := make([]byte, len(data))
	copy(copyData, data)

	header, rulesContext, _, err := cryption.ReadRulesData(data)
	if err != nil {
		t.Fatal(err)
	}
	version, rules, _, err := parseItems(header, rulesContext)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(version)
	for _, rule := range rules {
		t.Log("name:", rule.name, "description:", rule.description,
			"ruleType:", rule.ruleType, "adapter:", rule.adapter,
			"severity:", rule.severity, "hthreats:", rule.hthreats)
	}

	for i := 0; i < len(data); i++ {
		if data[i] != copyData[i] {
			t.Fatal("data changed")
		}
	}
}

func Test_compareVersion(t *testing.T) {
	type args struct {
		latestConf      *model.ATTCKRuleData
		toCompareHeader cryption.FileHeader
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "0",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 1,
						Version2: 0,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{2, 10},
				},
			},
			want: true,
		},
		{
			name: "1",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 1,
						Version2: 0,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{1, 10},
				},
			},
			want: true,
		},
		{
			name: "2",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 1,
						Version2: 103,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{1, 102},
				},
			},
			want: false,
		},
		{
			name: "3",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 2,
						Version2: 0,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{1, 10},
				},
			},
			want: false,
		},
		{
			name: "4",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 2,
						Version2: 0,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{1, 10},
				},
			},
			want: false,
		},
		{
			name: "5",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 1,
						Version2: 0,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{1, 10},
				},
			},
			want: true,
		},
		{
			name: "6",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 23,
						Version2: 0,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{1, 10},
				},
			},
			want: false,
		},
		{
			name: "6",
			args: args{
				latestConf: &model.ATTCKRuleData{
					ATTCKConfVersion: model.ATTCKConfVersion{
						Version1: 1,
						Version2: 10,
					},
				},
				toCompareHeader: cryption.FileHeader{
					Version: [2]uint16{1, 10},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersion(tt.args.latestConf, tt.args.toCompareHeader)
			if got != tt.want {
				t.Errorf("compareVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
