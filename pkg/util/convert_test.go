package util

import "testing"

func TestBytes2StringNoCopy(t *testing.T) {
	var buf = []byte("1234")
	s := Bytes2StringNoCopy(buf)
	t.Log(s)
}

func TestString2BytesNoCopy(t *testing.T) {
	var s = "1234"
	buf := String2BytesNoCopy(s)
	t.Log(buf)
}
