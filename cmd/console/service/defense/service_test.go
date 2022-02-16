package defense

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestImageName(t *testing.T) {
	res := strings.SplitN("tensorsecurity/scarecrow", ":", 2)
	t.Log(len(res))
}

func TestJson(t *testing.T) {
	ports := []int{8080, 6379}
	bytes, err := json.Marshal(ports)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(bytes))
}
func TestUnMarshal(t *testing.T) {
	s := "[8080,6379]"
	var ports []int
	err := json.Unmarshal([]byte(s), &ports)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ports)
}
