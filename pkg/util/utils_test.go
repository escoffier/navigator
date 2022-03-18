package util

import (
	"fmt"
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

func TestGenerateUUID(t *testing.T) {
	convey.Convey("TestGenerateUUID", t, func() {
		convey.So(GenerateUUID(fmt.Sprintf("%s-%s-%s", "CNNVD-202110-072", "linux-tools-4.15.0-64", "4.15.0-64.73")), convey.ShouldEqual, 490865440)
	})
	convey.Convey("TestGenerateUUID", t, func() {
		convey.So(GenerateUUID(fmt.Sprintf("%s-%s-%s", "CNNVD-201707-867", "libk5crypto3", "1.12+dfsg-2ubuntu5.1")), convey.ShouldEqual, 490865440)
	})

}
