package token

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTokenVerifyWithoutCacheValidate(t *testing.T) {
	issuer := NewJWTTokenManager(nil)

	admin := Payload{
		PortalEmail: "admin@163.com",
	}

	tokenString, err := issuer.IssueTo(admin)
	fmt.Println(tokenString)
	if err != nil {
		t.Fatal(err)
	}

	got, err := issuer.Verify(tokenString)

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, admin); diff != "" {
		t.Errorf("token validate failed: %s", diff)
	}
}
