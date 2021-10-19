package dal

import (
	"context"
	"testing"

	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func initLdapGroupDB(t *testing.T) {
	initDB(t)
	err := db.AutoMigrate(&model.LdapGroup{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateLdapGroup(t *testing.T) {
	initLdapGroupDB(t)
	err := CreateLdapGroup(context.TODO(), db, &model.LdapGroup{
		Name:    "test",
		Role:    "admin",
		Modules: "[\"2\",\"3\",\"4\"]",
	})
	if err != nil {
		if IsPostgresDuplicateError(err) {
			t.Log("duplicate")
		} else {
			t.Fatal(err)
		}
	}

	err = CreateLdapGroup(context.TODO(), db, &model.LdapGroup{
		Name:    "test2",
		Role:    "admin",
		Modules: "[\"2\",\"3\",\"4\"]",
	})
	if err != nil {
		if IsPostgresDuplicateError(err) {
			t.Log("duplicate")
		} else {
			t.Fatal(err)
		}
	}
}

func TestGetLdapGroupByName(t *testing.T) {
	initLdapGroupDB(t)
	group, err := GetLdapGroupByName(context.TODO(), db, "test")
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			t.Log("not found")
		} else {
			t.Fatal(err)
		}
	}
	t.Log(group)
}

func TestCheckLdapGroupExists(t *testing.T) {
	initLdapGroupDB(t)
	check, err := CheckLdapGroupExists(context.TODO(), db, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(check)
	check, err = CheckLdapGroupExists(context.TODO(), db, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(check)
}
func TestGetLdapGroupList(t *testing.T) {
	initLdapGroupDB(t)
	groups, err := GetLdapGroupList(context.TODO(), db, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		t.Log(group)
	}
}

func TestGetLdapGroupCount(t *testing.T) {
	initLdapGroupDB(t)
	count, err := GetLdapGroupCount(context.TODO(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(count)
}

func TestUpdateLdapGroup(t *testing.T) {
	initLdapGroupDB(t)
	err := UpdateLdapGroup(context.TODO(), db, &model.LdapGroup{
		ID:      4,
		Name:    "test3",
		Role:    "admin",
		Modules: "[\"2\",\"3\",\"4\"]",
	})
	if err != nil {
		if IsPostgresDuplicateError(err) {
			t.Log("duplicate")
		} else {
			t.Fatal(err)
		}
	}

	err = UpdateLdapGroup(context.TODO(), db, &model.LdapGroup{
		ID:      4,
		Name:    "test2",
		Role:    "",
		Modules: "[\"2\",\"3\",\"4\"]",
	})
	if err != nil {
		if IsPostgresDuplicateError(err) {
			t.Log("duplicate")
		} else {
			t.Fatal(err)
		}
	}
}

func TestDeleteLdapGroup(t *testing.T) {
	initLdapGroupDB(t)
	err := DeleteLdapGroup(context.TODO(), db, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteLdapGroup(context.TODO(), db, 0)
	if err != nil {
		t.Fatal(err)
	}
}
