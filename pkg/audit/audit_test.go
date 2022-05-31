package audit

import (
	"bytes"
	"encoding/json"
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
	name := ""
	ta := template.Must(template.New("action").Parse("启停租户{{.}}隔离策略"))
	var buf bytes.Buffer
	ta.Execute(&buf, name)
	t.Log(buf.String())

	ta1 := template.Must(template.New("action").Parse("启停租户隔离策略"))
	ta1.Execute(os.Stdout, name)
}
