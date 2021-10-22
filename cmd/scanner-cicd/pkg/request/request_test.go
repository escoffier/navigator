package request

import (
	"net/url"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUrlJoin(t *testing.T) {
	var a = []struct {
		host, path, except string
	}{
		{
			"http://www.baidu.com",
			"aaa/aaa",
			"http://www.baidu.com/aaa/aaa",
		},
		{
			"http://www.baidu.com",
			"/aaa/aaa",
			"http://www.baidu.com/aaa/aaa",
		},
		{
			"http://www.baidu.com/",
			"aaa/aaa",
			"http://www.baidu.com/aaa/aaa",
		},
		{
			"http://www.baidu.com/",
			"/aaa/aaa",
			"http://www.baidu.com/aaa/aaa",
		},
	}

	for _, v := range a {
		h, _ := url.Parse(v.host)
		h.Path = path.Join(h.Path, v.path)

		assert.Equal(t, h.String(), v.except)
	}
}
