package dal

import (
	"context"
	"testing"
)

func initOpenAPIDB(t *testing.T) {
	initDB(t)
}

func TestSaveAuthToken(t *testing.T) {
	initOpenAPIDB(t)
	var err = SaveAuthToken(context.TODO(), db, "testUser", "testToken")
	if err != nil {
		t.Fatal(err)
	}

	err = SaveAuthToken(context.TODO(), db, "testUser", "testToken")
	if err != nil {
		t.Fatal(err)
	}
}
