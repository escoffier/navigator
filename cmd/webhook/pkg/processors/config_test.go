package processors

import "testing"

func TestGetConfigFullPath(t *testing.T) {
	type args struct {
		configFile string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{name: "test1", args: args{configFile: "test1.yaml"}, want: "/etc/tensorsec/config/test1.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetConfigFullPath(tt.args.configFile); got != tt.want {
				t.Errorf("GetConfigFullPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
