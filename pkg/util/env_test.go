package util

import (
	"reflect"
	"testing"
)

func Test_getEnv(t *testing.T) {
	type args struct {
		envs []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "test1",
			args: args{envs: []string{"REDIS_PASSWORD=Redis12345", "SCANNER_URL=http://prod-scanner:8888", "ELASTIC_PASSWORD=Q6habYR43GD54MCm"}},
			want: []string{"REDIS_PASSWORD=******", "SCANNER_URL=http://prod-scanner:8888", "ELASTIC_PASSWORD=******"},
		},
		{
			name: "test2",
			args: args{envs: []string{"REDIS_PASSWOR=RedisPASSWORD12345", "MYSQLPWD=1234"}},
			want: []string{"REDIS_PASSWOR=RedisPASSWORD12345", "MYSQLPWD=******"},
		},
		{
			name: "test2",
			args: args{envs: []string{"REDIS_PASSWORD=RedisPASSWORD12345", "invalid envs"}},
			want: []string{"REDIS_PASSWORD=******"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeIdentificationEnvs(tt.args.envs)
			if !reflect.DeepEqual(got, tt.want) {

				t.Errorf("getEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}
