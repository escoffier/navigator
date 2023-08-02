package hm

import "testing"

func TestScanFile(t *testing.T) {
	hm := NewHMWebshell()
	hm.GenerateCmdDir("/tmp/webshell")
	hm.ScanFile("/tmp/webshell")
	result, err := hm.ReadAndCleanResult()
	if err != nil {
		t.Error(err)
	}
	// print result
	for _, item := range result {
		t.Logf("%+v", item)
	}

}
