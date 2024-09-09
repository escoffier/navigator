package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"text/template"
)

func TestData(t *testing.T) {
	type student struct {
		Name string
		ID   string
	}

	type foo struct {
		Name   string
		Gender string
	}
	bytes, err := json.Marshal(student{
		Name: "robbie",
		ID:   "123",
	})
	if err != nil {
		t.Fatal(err)
	}

	f := &foo{}

	err = json.Unmarshal(bytes, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(f.Name)
}

func TestTemplate(t *testing.T) {
	name := "aaa"
	ta := template.Must(template.New("action").Parse("启停租户{{.}}隔离策略"))
	var buf bytes.Buffer
	ta.Execute(&buf, name)
	fmt.Println(buf.String())
	t.Log(buf.String())

	ta1 := template.Must(template.New("action").Parse("启停租户隔离策略"))
	ta1.Execute(os.Stdout, name)
}

func TestTemplateSlice(t *testing.T) {
	name := []string{"segment", "123"}
	ta := template.Must(template.New("action").Parse("{{index . 0}}:{{index . 1}}"))
	var buf bytes.Buffer
	ta.Execute(&buf, name)
	fmt.Println(name)
	t.Fatal(buf.String())
	fmt.Println(buf.String())
	t.Log(buf.String())
}
