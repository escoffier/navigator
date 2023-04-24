package check

import (
	"fmt"
	"strings"
)

type FilterOpts struct {
	CheckList string
	GroupList string
	Scored    bool
	Unscored  bool
}

// Predicate a predicate on the given Group and Check arguments.
type Predicate func(group *Group, check *Check) bool

// NewRunFilter constructs a Predicate based on FilterOpts which determines whether tested Checks should be run or not.
func NewRunFilter(opts FilterOpts) (Predicate, error) {
	if opts.CheckList != "" && opts.GroupList != "" {
		return nil, fmt.Errorf("group option and check option can't be used together")
	}

	var groupIDs map[string]bool
	if opts.GroupList != "" {
		groupIDs = cleanIDs(opts.GroupList)
	}

	var checkIDs map[string]bool
	if opts.CheckList != "" {
		checkIDs = cleanIDs(opts.CheckList)
	}

	return func(g *Group, c *Check) bool {
		test := true
		if len(groupIDs) > 0 {
			_, ok := groupIDs[g.ID]
			test = test && ok
		}

		if len(checkIDs) > 0 {
			_, ok := checkIDs[c.ID]
			test = test && ok
		}

		test = test && (opts.Scored && c.Scored || opts.Unscored && !c.Scored)

		return test
	}, nil
}

// cleanIDs cleans ids from provided list
func cleanIDs(list string) map[string]bool {
	list = strings.Trim(list, ",")
	ids := strings.Split(list, ",")

	set := make(map[string]bool)

	for _, id := range ids {
		id = strings.Trim(id, " ")
		set[id] = true
	}

	return set
}
