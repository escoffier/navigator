package check

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRunFilter(t *testing.T) {
	type TestCase struct {
		Name       string
		FilterOpts FilterOpts
		Group      *Group
		Check      *Check

		Expected bool
	}

	testCases := []TestCase{
		{
			Name:       "Should return true when scored flag is enabled and check is scored",
			FilterOpts: FilterOpts{Scored: true, Unscored: false},
			Group:      &Group{},
			Check:      &Check{Scored: true},
			Expected:   true,
		},
		{
			Name:       "Should return false when scored flag is enabled and check is not scored",
			FilterOpts: FilterOpts{Scored: true, Unscored: false},
			Group:      &Group{},
			Check:      &Check{Scored: false},
			Expected:   false,
		},

		{
			Name:       "Should return true when unscored flag is enabled and check is not scored",
			FilterOpts: FilterOpts{Scored: false, Unscored: true},
			Group:      &Group{},
			Check:      &Check{Scored: false},
			Expected:   true,
		},
		{
			Name:       "Should return false when unscored flag is enabled and check is scored",
			FilterOpts: FilterOpts{Scored: false, Unscored: true},
			Group:      &Group{},
			Check:      &Check{Scored: true},
			Expected:   false,
		},

		{
			Name:       "Should return true when group flag contains group's ID",
			FilterOpts: FilterOpts{Scored: true, Unscored: true, GroupList: "G1,G2,G3"},
			Group:      &Group{ID: "G2"},
			Check:      &Check{},
			Expected:   true,
		},
		{
			Name:       "Should return false when group flag doesn't contain group's ID",
			FilterOpts: FilterOpts{GroupList: "G1,G3"},
			Group:      &Group{ID: "G2"},
			Check:      &Check{},
			Expected:   false,
		},

		{
			Name:       "Should return true when check flag contains check's ID",
			FilterOpts: FilterOpts{Scored: true, Unscored: true, CheckList: "C1,C2,C3"},
			Group:      &Group{},
			Check:      &Check{ID: "C2"},
			Expected:   true,
		},
		{
			Name:       "Should return false when check flag doesn't contain check's ID",
			FilterOpts: FilterOpts{CheckList: "C1,C3"},
			Group:      &Group{},
			Check:      &Check{ID: "C2"},
			Expected:   false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			filter, _ := NewRunFilter(testCase.FilterOpts)
			assert.Equal(t, testCase.Expected, filter(testCase.Group, testCase.Check))
		})
	}

	t.Run("Should return error when both group and check flags are used", func(t *testing.T) {
		// given
		opts := FilterOpts{GroupList: "G1", CheckList: "C1"}
		// when
		_, err := NewRunFilter(opts)
		// then
		assert.EqualError(t, err, "group option and check option can't be used together")
	})
}
