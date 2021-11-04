package inject

import (
	"fmt"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	"strings"
	"testing"
)

func TestTemplate(t *testing.T) {

	tmpstr, err := ioutil.ReadFile("testdata/sidecar-template-1.yaml")
	if err != nil {
		t.Fatal(err)

	}

	data := SidecarTemplateData{
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Ports: []corev1.ContainerPort{{ContainerPort: 8899, Protocol: "TCP"}}}}},
		ProxyConfig: DefaultProxyConfig(),
	}
	injectedYAML, err := parseTemplate(string(tmpstr), data)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile("injected.yaml", injectedYAML.Bytes(), 0644)
	if err != nil {
		t.Log(err)
	}
	fmt.Printf("%s", injectedYAML.String())

}

func TestOwnerName(t *testing.T) {
	name := "vulnweb-test-fc9d89f6f-"
	n := strings.LastIndex(name, "-")
	ss := strings.SplitAfter(name, "-")
	t.Log(ss)
	rsName := name[:n]
	n = strings.LastIndex(rsName, "-")
	deploymentName := rsName[:n]

	t.Log(rsName)
	t.Log(deploymentName)

}
