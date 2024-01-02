package adaptStore

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

func Test_TaskStatusCheck(t *testing.T) {
	l := []struct {
		current int
		next    []int
		isValid []bool
	}{
		{
			consts.Pending,
			[]int{
				consts.Pending,
				consts.InProgress,
				consts.Pause,
				consts.Terminate,
				consts.End,
			},
			[]bool{true, true, true, true, false},
		},

		{
			consts.InProgress,
			[]int{
				consts.Pending,
				consts.InProgress,
				consts.Pause,
				consts.Terminate,
				consts.End,
			},
			[]bool{false, true, true, true, true},
		},

		{
			consts.Pause,
			[]int{
				consts.Pending,
				consts.InProgress,
				consts.Pause,
				consts.Terminate,
				consts.End,
			},
			[]bool{true, false, true, true, false},
		},

		{
			consts.Terminate,
			[]int{
				consts.Pending,
				consts.InProgress,
				consts.Pause,
				consts.Terminate,
				consts.End,
			},
			[]bool{false, false, false, true, false},
		},

		{
			consts.End,
			[]int{
				consts.Pending,
				consts.InProgress,
				consts.Pause,
				consts.Terminate,
				consts.End,
			},
			[]bool{false, false, false, false, true},
		},
	}

	for _, v := range l {
		for j := range v.next {
			err := StatusCheck(uint8(v.current), uint8(v.next[j]))
			assert.Equal(t, v.isValid[j], err == nil)
		}
	}
}
