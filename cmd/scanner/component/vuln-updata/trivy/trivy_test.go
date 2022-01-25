package trivyupdata

import "testing"

func TestGetTrivyDb(t *testing.T) {
	var trivy TrivyUpdata
	trivy.config.DbPath = "/tmp/"
	_ = trivy.GetTrivyDb()
}
