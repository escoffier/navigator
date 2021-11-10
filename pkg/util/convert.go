package util

import (
	"reflect"
	"unsafe"
)

func StringSetToArray(hash map[string]struct{}) []string {
	var result = make([]string, 0, len(hash))
	for str := range hash {
		result = append(result, str)
	}

	return result
}

func FilterDuplicateIntArray(arr []int) []int {
	hash := make(map[int]struct{})
	for _, v := range arr {
		hash[v] = struct{}{}
	}
	if len(hash) == len(arr) {
		return arr
	}

	result := make([]int, 0, len(hash))
	for v := range hash {
		result = append(result, v)
	}

	return result
}

func FilterDuplicateStringArray(arr []string) []string {
	hash := make(map[string]struct{})
	for _, v := range arr {
		hash[v] = struct{}{}
	}
	if len(hash) == len(arr) {
		return arr
	}

	result := make([]string, 0, len(hash))
	for v := range hash {
		result = append(result, v)
	}

	return result
}

func StringArrToMap(arr []string) map[string]struct{} {
	hash := make(map[string]struct{})
	for _, v := range arr {
		hash[v] = struct{}{}
	}
	return hash
}

type Bytes []byte

func Bytes2StringNoCopy(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}

func String2BytesNoCopy(s string) Bytes {
	var bh reflect.SliceHeader
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data, bh.Len, bh.Cap = sh.Data, sh.Len, sh.Len
	return *(*Bytes)(unsafe.Pointer(&bh))
}
