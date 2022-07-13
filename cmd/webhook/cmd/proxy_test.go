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
		{
			name: "test2",
			args: args{host: "http://navi-proxy:10000"},
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

func TestParseHost(t *testing.T) {
	url, err := url.Parse("https://navi-proxy:10000")
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(url.Scheme)
}
