package utils

import (
	"fmt"
	"testing"
)

func TestIPToInt(t *testing.T) {
	v := IP4ToInt("10.0.246.79")
	fmt.Println(v)
	s := InttoIP4(int64(v))
	fmt.Println(s)
}
