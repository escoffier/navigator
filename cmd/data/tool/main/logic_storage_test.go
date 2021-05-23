package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"os"
	"testing"
)

func initDumpHotLogicStorageRequirement(t *testing.T) {
	var envVars = map[string]string{
		env.MongoEndpoint:       "127.0.0.1:27017",
		env.MongoDatabase:       "vegeta",
		env.MongoReadPreference: "primary",

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
