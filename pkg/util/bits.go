package util

// value从右到左的第flag位设置成0
func SetBit0(value uint64, flag uint64) uint64 {
	value &= ^(1 << flag)
	return value
}

// value从右到左的第flag位设置成1
func SetBit1(value uint64, flag uint64) uint64 {
	value |= 1 << (flag)
	return value
}

func ExistBit1(value uint64, flag uint64) bool {
	return (value>>flag)&1 == 1
}

func ExistBit0(value uint64, flag uint64) bool {
	return (value>>flag)&1 == 0
}

func ExistInStringSlice(value []string, flag string) bool {
	for i := range value {
		if flag == value[i] {
			return true
		}
	}
	return false
}

func ExistInInt64Slice(value []int64, flag int64) bool {

	for i := range value {
		if flag == value[i] {
			return true
		}
	}
	return false
}
