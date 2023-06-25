package microseg

import (
	"net"
	"testing"
	"time"
)

func Test_policyCliet_DeletePolicy(t *testing.T) {
	type fields struct {
		conn          *net.UnixConn
		writeDeadline time.Time
	}
	type args struct {
		rule *PolicyRule
	}

	cli, err := NewPolicyClient("/tmp/echo.socket")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "test-1",
			fields: fields{},
			args: args{
				rule: &PolicyRule{
					MessageType: 4,
					PolicyName:  "test-policy",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// cli := &policyCliet{
			// 	conn:          tt.fields.conn,
			// 	writeDeadline: tt.fields.writeDeadline,
			// }
			if err := cli.DeletePolicy(tt.args.rule); (err != nil) != tt.wantErr {
				t.Errorf("policyCliet.DeletePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			// time.Sleep(time.Second * 5)
		})
	}
	// cli.Stop()
}
