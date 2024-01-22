package adaptStore

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts/preConsts"
)

func Test_TaskStatusCheck(t *testing.T) {
	l := []struct {
		current int
		next    []int
		isValid []bool
	}{
		{
			preConsts.Pending,
			[]int{
				preConsts.Pending,
				preConsts.InProgress,
				preConsts.Pause,
				preConsts.Terminate,
				preConsts.End,
			},
			[]bool{true, true, true, true, false},
		},

		{
			preConsts.InProgress,
			[]int{
				preConsts.Pending,
				preConsts.InProgress,
				preConsts.Pause,
				preConsts.Terminate,
				preConsts.End,
			},
			[]bool{false, true, true, true, true},
		},

		{
			preConsts.Pause,
			[]int{
				preConsts.Pending,
				preConsts.InProgress,
				preConsts.Pause,
				preConsts.Terminate,
				preConsts.End,
			},
			[]bool{true, false, true, true, false},
		},

		{
			preConsts.Terminate,
			[]int{
				preConsts.Pending,
				preConsts.InProgress,
				preConsts.Pause,
				preConsts.Terminate,
				preConsts.End,
			},
			[]bool{false, false, false, true, false},
		},

		{
			preConsts.End,
			[]int{
				preConsts.Pending,
				preConsts.InProgress,
				preConsts.Pause,
				preConsts.Terminate,
				preConsts.End,
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
