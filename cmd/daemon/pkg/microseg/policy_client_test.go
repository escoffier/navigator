package microseg

import (
	"net"
	"testing"
	"time"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
)

func Test_policyCliet_DeletePolicy(t *testing.T) {
	type fields struct {
		conn          *net.UnixConn
		writeDeadline time.Time
	}
	type args struct {
		rule *PolicyRule
	}

	agentCli, err := heavyagent.NewClient("/tmp/echo.socket")
	cli := NewPolicyClient(agentCli)
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
			if err := cli.DeletePolicy(tt.args.rule); (err != nil) != tt.wantErr {
				t.Errorf("policyCliet.DeletePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			// time.Sleep(time.Second * 5)
		})
	}
	// cli.Stop()
}
