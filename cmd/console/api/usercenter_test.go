package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJsonBind(t *testing.T) {
	type reqAddUser struct {
		UserName string   `json:"userName" binding:"required,dive,max=32"`
		RoleName string   `json:"roleName" binding:"required,dive,oneof=admin normal"`
		ModuleID []string `json:"moduleID"`
	}

	var req reqAddUser
	var err = json.Unmarshal([]byte(`{"username": "1234172312312312312312312312312311231", "roleName": "nonsense"}`), &req)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(req)
}

func TestTrimUsername(t *testing.T) {
	username := "xx@qq.com "
	t.Log(strings.TrimSpace(username) == "xx@qq.com")
}
