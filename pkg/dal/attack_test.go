package dal

import (
	"context"
	"os"
	"testing"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func TestLoadATTCKConfData(t *testing.T) {
	initDB(t)
	data, err := LoadATTCKConfDataByVersion1(context.TODO(), db, 1)
	if err != nil && err != ErrATTCKConfDataNotFound {
		t.Fatal(err)
	}
	t.Log(data)
}

func TestLoadATTCKConfVersion(t *testing.T) {
	initDB(t)
	version, err := LoadATTCKConfVersion(context.TODO(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(version)
}

func TestLoadATTCKConfVersions(t *testing.T) {
	initDB(t)
	total, versions, err := LoadATTCKConfVersions(context.TODO(), db, 0, 10, 1)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(total, versions)
}

func TestLoadATTCKRuleMasks(t *testing.T) {
	initDB(t)
	masks, err := LoadATTCKRuleMasks(context.TODO(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(masks)
}

func TestLoadATTCKRuleMaskVersion(t *testing.T) {
	initDB(t)
	version, err := LoadATTCKRuleMaskVersion(context.TODO(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(version)
}

func TestSaveATTCKConfData(t *testing.T) {
	initDB(t)
	content, err := os.ReadFile("encrypt_rule.data")
	if err != nil {
		t.Fatal(err)
	}
	baseOffset, err := SaveATTCKConfData(context.TODO(), db, &model.ATTCKRuleData{
		Content: content,
		ATTCKConfVersion: model.ATTCKConfVersion{
			Version1:  1,
			Version2:  0,
			Username:  "testUsername",
			CreatedAt: time.Now(),
		},
	}, []string{"testDelete1", "testDelete2"})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(baseOffset)
}

func TestUpdateRuleMask(t *testing.T) {
	initDB(t)
	var err = UpdateRuleMask(context.TODO(), db, []*model.ATTCKRuleMask{
		{
			Name: "add1",
		},
		{
			Name: "add2",
		},
	}, []string{"del1", "del2"})
	if err != nil {
		t.Fatal(err)
	}
}
