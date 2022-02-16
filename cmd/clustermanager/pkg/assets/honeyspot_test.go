package assets

import (
	"fmt"
	"testing"
)

func TestGetBaitServiceId(t *testing.T) {
	id, err := getBaitServiceID("honeyspot-893196037")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(id)
	t.Log(id)
}
