package assets

import (
	"encoding/json"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/containers"
	"net/url"
	"reflect"
	"testing"
)

func TestImageUUID(t *testing.T) {
	data := map[string][]uint32{"uuids": []uint32{1234, 45676, 8766666}}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(body))
}

func Test_getUniqueUUIDs(t *testing.T) {
	type args struct {
		uids []uint32
	}
	tests := []struct {
		name string
		args args
		want []uint32
	}{
		// TODO: Add test cases.
		{
			name: "test-1",
			args: args{uids: []uint32{1, 2, 3, 4, 4, 5, 6, 6, 4, 7}},
			want: []uint32{1, 2, 3, 4, 5, 6, 7},
		},
		{
			name: "test-2",
			args: args{uids: []uint32{1, 22, 22, 4, 0, 5, 5, 6, 4, 4}},
			want: []uint32{1, 22, 4, 0, 5, 6},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containers.getUniqueUUIDs(tt.args.uids); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getUniqueUUIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getImageUrl(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:    "test-1",
			args:    args{image: "harbor.tensorsecurity.com/test/drift@sha256:2cd6ac8e73539727fcad062f17e955eb6ee8e2e2a0b76583dca2dd9f8d59f2d3"},
			want:    "harbor.tensorsecurity.com",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getImageUrl(tt.args.image)
			if (err != nil) != tt.wantErr {
				t.Errorf("getImageUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getImageUrl() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUrl(t *testing.T) {
	u, err := url.Parse("https://harbor-prod.tensorsecurity.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(u.Scheme)
	t.Log(u.Host)
}
