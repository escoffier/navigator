package hunter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateReportURL(t *testing.T) {
	url1, err := generateReportURL("https://console.tensorsecurity.cn")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(url1)

	url2, err := generateReportURL("https://console.tensorsecurity.cn/")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(url2)
	assert.Equal(t, url1, url2)
}
