package inject

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
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

func TestInjector_Inject(t *testing.T) {
	tmpl, err := ioutil.ReadFile("testdata/sidecar-template-2.yaml")
	if err != nil {
		t.Fatal(err)

	}

	jsonPod, err := ioutil.ReadFile("testdata/kubeorigin.json")

	var pod corev1.Pod
	if json.Unmarshal(jsonPod, &pod); err != nil {
		t.Fatal(err)

	}

	paras := InjectionParameters{
		Template:    string(tmpl),
		ProxyConfig: DefaultProxyConfig(),
	}
	injector, err := NewInjector(&paras)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := injector.Inject(&pod, "test-service")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v", string(resp))
}
