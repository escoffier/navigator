package api

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	v1 "k8s.io/api/core/v1"
	"testing"
)

func Test_parseImage(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 string
		want2 string
	}{
		{
			name:  "test-1",
			args:  args{image: "registry.t-appagile.com/tensorsecurity/tensorsec-console:testcn"},
			want:  "registry.t-appagile.com",
			want1: "tensorsecurity/tensorsec-console",
			want2: "testcn",
		},
		{
			name:  "test-12",
			args:  args{image: "registry.t-appagile.com/tensorsecurity/tensorsec-console"},
			want:  "registry.t-appagile.com",
			want1: "tensorsecurity/tensorsec-console",
			want2: "",
		},
		{
			name:  "test-2",
			args:  args{image: "192.168.23.1:8080/tensorsecurity/tensorsec-console:testcn"},
			want:  "192.168.23.1:8080",
			want1: "tensorsecurity/tensorsec-console",
			want2: "testcn",
		},
		{
			name:  "test-3",
			args:  args{image: "192.168.23.1:8080/tensorsecurity/tensorsec-console:"},
			want:  "192.168.23.1:8080",
			want1: "tensorsecurity/tensorsec-console",
			want2: "",
		},
		{
			name:  "test-4",
			args:  args{image: "192.168.23.1:8080/tensorsecurity/tensorsec-console"},
			want:  "192.168.23.1:8080",
			want1: "tensorsecurity/tensorsec-console",
			want2: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := parseImage(tt.args.image)
			if got != tt.want {
				t.Errorf("parseImage() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("parseImage() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("parseImage() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func TestCpContainer(t *testing.T) {
	container := model.TensorContainer{
		Ports: []v1.ContainerPort{
			{Name: "1", Protocol: "tcp", ContainerPort: 80},
			{Name: "2", Protocol: "udp", ContainerPort: 80},
		},
	}

	value, err := container.Ports.Value()
	if err != nil {
		return
	}
	t.Logf("%s", string(value.([]byte)))

	var cm1 model.ContainerPorts

	//err = json.Unmarshal(value.([]byte), &cm1)
	//if err != nil {
	//	t.Fatal(err)
	//	return
	//}
	cm1.Scan(value)
	t.Logf("%v", cm1)

	var ports []v1.ContainerPort
	ports = make([]v1.ContainerPort, len(container.Ports))
	copy(ports, container.Ports)
	t.Logf("%v", ports)
}

func TestSliceField(t *testing.T) {
	data := []byte(`[{"containerPort": 9080}]`)
	var cmp model.ContainerPorts
	err := cmp.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", cmp)
}
