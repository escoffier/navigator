package util

import (
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

// value从右到左的第flag位设置成0
func SetBit0(value uint64, flag uint64) uint64 {
	pre := value
	pre &= ^(1 << flag)
	return pre
}

// value从右到左的第flag位设置成1
func SetBit1(value uint64, flag uint64) uint64 {
	pre := value
	pre |= 1 << (flag)
	return pre
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

func MaxInt64(data ...int64) int64 {
	if len(data) == 0 {
		return 0
	}
	ans := data[0]
	for i := range data {
		if data[i] > ans {
			ans = data[i]
		}
	}
	return ans
}

func MinInt64(data ...int64) int64 {
	if len(data) == 0 {
		return 0
	}
	ans := data[0]
	for i := range data {
		if data[i] < ans {
			ans = data[i]
		}
	}
	return ans
}

// 比较版本号
// 如果 version1 > version2 返回 1，
// 如果 version1 < version2 返回 -1，
// 除此之外返回 0。
// 版本号格式是：2.11.1-amd ，可能有字母，所以只取 - 之前的比较
func CompareVersion(version1 string, version2 string) int {
	// 本地prod 环境中会使用 latest 版本号
	if version1 == consts.ScannerVersionLatest {
		return 1
	}
	split3 := strings.Split(version1, "-")
	if len(split3) > 0 {
		version1 = split3[0]
	}

	split4 := strings.Split(version2, "-")
	if len(split4) > 0 {
		version2 = split4[0]
	}

	split1 := strings.Split(version1, ".")
	split2 := strings.Split(version2, ".")
	len1 := len(split1)
	len2 := len(split2)
	if len1 > len2 {
		for i := 0; i <= len1-len2; i++ {
			split2 = append(split2, "0")
		}
	} else if len2 > len1 {
		for i := 0; i < len2-len1; i++ {
			split1 = append(split1, "0")
		}
	}
	for i := 0; i < len(split1); i++ {
		ato1, _ := strconv.Atoi(split1[i])
		ato2, _ := strconv.Atoi(split2[i])
		if ato1 > ato2 {
			return 1
		} else if ato1 < ato2 {
			return -1
		}
	}
	return 0
}
