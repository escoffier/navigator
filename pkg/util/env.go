package util

import (
	"os"
	"strconv"
)

const (
	EnvKeyTestNonSingletonPod = "ENV_TEST_NON_SINGLETON"
)

var (
	testNonSingletonPod = false
)

func init() {
	val := os.Getenv(EnvKeyTestNonSingletonPod)
	if val == "" {
		return
	}
	bl, err := strconv.ParseBool(val)
	if err == nil && bl {
		testNonSingletonPod = true
	}
}

func IsNonSingletonPodInTestingEnv() bool {
	return testNonSingletonPod
}
