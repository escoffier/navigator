package util

import "strconv"

func Uint32sToStrings(u32s []uint32) []string {
	var strs []string
	for _, u32 := range u32s {
		strs = append(strs, strconv.FormatUint(uint64(u32), 10))
	}
	return strs
}
