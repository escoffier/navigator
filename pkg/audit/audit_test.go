package audit

import (
	"encoding/json"
	"testing"
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
