package hunter

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateReportURL(t *testing.T) {
	err := os.Setenv(consoleBaseURLEnv, "https://console.tensorsecurity.cn")
	if err != nil {
		t.Fatal(err)
	}

	url1, err := generateReportURL()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(url1)

	err = os.Setenv(consoleBaseURLEnv, "https://console.tensorsecurity.cn/")
	if err != nil {
		t.Fatal(err)
	}

	url2, err := generateReportURL()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(url2)
	assert.Equal(t, url1, url2)
}
