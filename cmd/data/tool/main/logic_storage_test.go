package main

import (
	"os"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
)

func initDumpHotLogicStorageRequirement(t *testing.T) {
	var envVars = map[string]string{
		env.PostgresHost:     "localhost",
		env.PostgresUser:     "pguser",
		env.PostgresDBName:   "tensorsecurity",
		env.PostgresSSLMode:  "disable",
		env.PostgresPassword: "pgpassword",

		env.ConfPath: "./test-hot-logic-conf.json",
	}

	for key, val := range envVars {
		if err := os.Setenv(key, val); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDumpHotLogicStorage(t *testing.T) {
	initDumpHotLogicStorageRequirement(t)
	if err := DumpHotLogicStorage(nil); err != nil {
		t.Fatal(err)
	}
}
