package api

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestValidServicename(t *testing.T) {
	// t.Log(isResourceNameValid("&&"))
	// rscExp, err := regexp.Compile("^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	names := []string{
		"tomcatAjp",
		"aaaa",
		"1111",
		"honeyspot-909563094-ddc305-vsewrasdawqe12321wwawsadasdwqe12adsadaq",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			// ok := rscExp.MatchString(name)
			ok := isResourceNameValid(name)
			t.Log(ok)
			if !ok {
				t.Errorf("test case failed for %s", name)
			}
		})
	}
}

func TestQualifiedNmae(t *testing.T) {
	result := validation.IsDNS1123Subdomain("tomcatAjp")
	if len(result) != 0 {
		for _, r := range result {
			t.Log(r)
		}
		t.Fail()
	}
}
