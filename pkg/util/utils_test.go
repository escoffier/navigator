package util

import (
	"testing"

	"github.com/smartystreets/goconvey/convey"
)

func TestDeDuplicationInt64Slice(t *testing.T) {
	convey.Convey("Test de duplication ", t, func() {
		convey.So(len(DeDuplicationInt64Slice([]int64{1, 2, 3, 2, 3, 1})), convey.ShouldEqual, 3)
	})
	convey.Convey("Test empty ", t, func() {
		convey.So(len(DeDuplicationInt64Slice([]int64{})), convey.ShouldEqual, 0)
	})
	convey.Convey("Test nil ", t, func() {
		convey.So(DeDuplicationInt64Slice(nil), convey.ShouldNotBeNil)
	})
}
