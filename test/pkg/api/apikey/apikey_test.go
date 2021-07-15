package apikey

import (
	"gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
	"testing"
)

func TestValidApiKey(t *testing.T) {
	t.Log("start test api valid")
	user := "tensorsec-cicd-user"
	valid, err := apikey.ValidateApiKey("dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv", user)
	if err != nil {
		t.Fatalf("not a valid api key,user %s,err %v", user, err)
	}
	if valid {
		t.Log("valid")
	} else {
		t.Fatalf("not valid api key")
	}
	t.Log("end")
}
