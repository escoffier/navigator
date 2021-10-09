package model

import "testing"

func TestManager(t *testing.T) {
	m := Managers{"123", "456"}
	value, err := m.Value()
	if err != nil {
		return
	}
	t.Logf("%v", string(value.([]byte)))
}
