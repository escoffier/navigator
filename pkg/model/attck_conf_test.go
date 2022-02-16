package model

import "testing"

func TestGetInfoFromOutput(t *testing.T) {
	type args struct {
		k      string
		output string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "rule_type",
			args: args{
				k:      "rule_type=",
				output: "Gaining sensitive information in Watson (zh_msg=Watson：通过主动防御检测到web目录文件访问,rule_type=Privilege_Escalation,fd.name=%fd.name,proc_pid=%proc.pid,proc_ppid=%proc.ppid,proc_cmdline=%proc.cmdline,proc_pname=%proc.pname,pod_id=%k8s.pod.id,syscall_name=%syscall.type,user=%user.name)",
			},
			want: "Privilege_Escalation",
		},
		{
			name: "user",
			args: args{
				k:      "user=",
				output: "Gaining sensitive information in Watson (zh_msg=Watson：通过主动防御检测到web目录文件访问,rule_type=Privilege_Escalation,fd.name=%fd.name,proc_pid=%proc.pid,proc_ppid=%proc.ppid,proc_cmdline=%proc.cmdline,proc_pname=%proc.pname,pod_id=%k8s.pod.id,syscall_name=%syscall.type,user=%user.name)",
			},
			want: "%user.name",
		},
		{
			name: "fd.name",
			args: args{
				k:      "fd.name=",
				output: "Gaining sensitive information in Watson (zh_msg=Watson：通过主动防御检测到web目录文件访问,rule_type=Privilege_Escalation,fd.name=%fd.name %containerInfo proc_pid=%proc.pid,proc_ppid=%proc.ppid,proc_cmdline=%proc.cmdline,proc_pname=%proc.pname,pod_id=%k8s.pod.id,syscall_name=%syscall.type,user=%user.name)",
			},
			want: "%fd.name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetInfoFromOutput(tt.args.k, tt.args.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInfoFromOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetInfoFromOutput() = %v, want %v", got, tt.want)
			}
		})
	}
}
