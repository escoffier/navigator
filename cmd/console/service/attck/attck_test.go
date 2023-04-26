package attck

import (
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/cryption"
)

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
