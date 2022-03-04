package store

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

// StatusCheck 检查当前状态是否可以流转到下一个状态
func StatusCheck(current, next uint8) error {

	if current == next {
		return nil
	}

	// 当前状态为 等待中 或者 运行中 时，改变状态为 暂停中、已终止、运行
	// 当前状态为 已暂停，改变状态为 等待中、已终止
	// 当前状态为 运行，改变状态为 暂停、终止、完成
	if (current == consts.Pending && (next == consts.Pause || next == consts.Terminate || next == consts.InProgress)) ||
		(current == consts.InProgress && (next == consts.Pause || next == consts.End || next == consts.Terminate)) ||
		(current == consts.Pause && (next == consts.Pending || next == consts.Terminate)) {
		return nil
	}

	return fmt.Errorf("invalid status change: %d -> %d", current, next)
}

func InSlice(v string, in []string) bool {
	for i := range in {
		if v == in[i] {
			return true
		}
	}
	return false
}

// 取交集
func UnionSlice(vules ...[]int64) []int64 {
	all := 0
	ext := make(map[int64]int)
	for i := range vules {
		if len(vules[i]) > 0 {
			all++
		}
		for j := range vules[i] {
			ext[vules[i][j]]++
		}
	}
	ans := make([]int64, 0)
	for k, v := range ext {
		if v == all {
			ans = append(ans, k)
		}
	}
	return ans
}
