package util

import (
	"testing"
)

func TestGetAddres(t *testing.T) {
	t.Log(GetMacAddrs())
	t.Log(GetIPs())
}
