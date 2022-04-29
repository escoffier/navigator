package model

import (
	"sort"
	"testing"

	"github.com/smartystreets/goconvey/convey"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
)

func TestCnvdMetadatas(t *testing.T) {

	cm1 := cnvd.Metadata{
		Number:      "1",
		Title:       "11",
		Severity:    "111",
		RefLink:     "1111",
		Description: "11111",
	}

	cm2 := cnvd.Metadata{
		Number:      "22",
		Title:       "222",
		Severity:    "2222",
		RefLink:     "2222",
		Description: "22222",
	}

	convey.Convey("TestCnvdMetadatas sort", t, func() {
		var res []cnvd.Metadata
		sort.Sort(CnvdMetadatas(res))
		convey.So(res, convey.ShouldBeNil)
	})

	convey.Convey("TestCnvdMetadatas sort", t, func() {
		res := []cnvd.Metadata{cm2, cm1}
		sort.Sort(CnvdMetadatas(res))
		convey.So(res, convey.ShouldResemble, []cnvd.Metadata{cm2, cm1})
	})

	convey.Convey("TestCnvdMetadatas sort", t, func() {
		res := []cnvd.Metadata{cm1, cm2}
		sort.Sort(CnvdMetadatas(res))
		convey.So(res, convey.ShouldResemble, []cnvd.Metadata{cm2, cm1})
	})

}
