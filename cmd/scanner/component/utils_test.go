package component

import (
	"testing"

	"github.com/smartystreets/goconvey/convey"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func TestCalculateVulnScore(t *testing.T) {
	sc := model.ScanImage{VulnInfo: make([]*model.Vuln, 0)}
	vulnName := "hello1"
	cus := map[string]model.RejectVuln{}

	cus[vulnName] = model.RejectVuln{
		RejectPolicyID: 1,
		Name:           vulnName,
		RejectPolicy:   model.RejectPolicyReject,
	}

	convey.Convey("Test CalculateVulnScore no vuln ", t, func() {
		convey.So(CalculateVulnScore(sc, cus), convey.ShouldEqual, 50)
	})

	sc.VulnInfo = append(sc.VulnInfo, &model.Vuln{Name: vulnName, SeverityInt: model.SeverityCriticalInt, Severity: model.SeverityCritical})

	convey.Convey("Test CalculateVulnScore has critical vuln ", t, func() {
		convey.So(CalculateVulnScore(sc, cus), convey.ShouldEqual, 25)
	})

	cus[vulnName] = model.RejectVuln{
		RejectPolicyID: 1,
		Name:           vulnName,
		RejectPolicy:   model.RejectPolicyIgnore,
	}

	convey.Convey("Test CalculateVulnScore has critical,bug reject policy is ignore", t, func() {
		convey.So(CalculateVulnScore(sc, cus), convey.ShouldEqual, 50)
	})

}
