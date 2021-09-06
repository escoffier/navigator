package cmd

import (
	"net/url"
	"reflect"
	"testing"
)

func Test_getTargetUrl(t *testing.T) {
	type args struct {
		host string
	}
	tests := []struct {
		name string
		args args
		want *url.URL
	}{
		{
			name: "test1",
			args: args{host: "http://console-test-cn.tensorsecurity.cn"},
			want: &url.URL{Scheme: "https", RawQuery: "", Path: "", Host: ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getTargetUrl(tt.args.host, ""); !reflect.DeepEqual(got, tt.want) {
				t.Log(got.String())
				t.Errorf("getTargetUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}
