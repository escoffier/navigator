package imagevalidator

import (
	"reflect"
	"testing"
)

func Test_loadConfig(t *testing.T) {
	type args struct {
		str string
	}

	tests := []struct {
		name    string
		args    args
		want    *Config
		wantErr bool
	}{
		{
			name: "test1",
			args: args{str: "../../config/imagevalidator.yaml"},
			want: &Config{
				ValidatorUrl:      "",
				ImageValidateHost: "",
				IgnoredNameSpaces: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadConfig(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}
