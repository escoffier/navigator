package dal

import (
	"context"
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func initOpenAPIDB(t *testing.T) {
	initDB(t)
	err := db.AutoMigrate(&model.OpenAPIAuthToken{})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("init db success")
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
