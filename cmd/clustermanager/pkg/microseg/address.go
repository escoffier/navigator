package microseg

import (
	"sort"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

type AddressSlice []crdv1alpha1.Address

func (x AddressSlice) Len() int           { return len(x) }
func (x AddressSlice) Less(i, j int) bool { return x[i].IP < x[j].IP }
func (x AddressSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

func (x AddressSlice) Sort() { sort.Sort(x) }
