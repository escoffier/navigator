package notifyhandler

import (
	"testing"

	"github.com/badoux/checkmail"
	"github.com/stretchr/testify/assert"
)

var (
	handler *Handler
)

func TestMailCheck(t *testing.T) {
	assert.Equal(t, nil, checkmail.ValidateFormat("weichangan@tensorsecurity.cn"))
	assert.Equal(t, checkmail.ErrBadFormat, checkmail.ValidateFormat("nonsense"))
}
