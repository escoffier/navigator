package util

import "testing"

func TestMultimap_Put(t *testing.T) {
	m := make(Multimap, 5)
	type args struct {
		key    string
		values []interface{}
	}
	tests := []struct {
		name string
		m    Multimap
		args args
	}{
		{
			name: "1",
			m:    m,
			args: args{
				key:    "one",
				values: []interface{}{"ok"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.m.Put(tt.args.key, tt.args.values...)
			if len(tt.m.Get(tt.args.key)) == 0 {
				t.Errorf("error for put")
			}
		})
	}
}
