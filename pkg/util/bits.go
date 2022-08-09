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
