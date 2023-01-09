package assets

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestImageUUID(t *testing.T) {
	data := map[string][]uint32{"uuids": {1234, 45676, 8766666}}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(body))
}

func TestUrl(t *testing.T) {
	u, err := url.Parse("https://harbor-prod.tensorsecurity.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(u.Scheme)
	t.Log(u.Host)
}
