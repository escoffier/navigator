package util

import (
	"fmt"
	"testing"

	"github.com/smartystreets/goconvey/convey"
)

func TestGenerateUUID(t *testing.T) {
	convey.Convey("TestGenerateUUID", t, func() {
		convey.So(GenerateUUID(fmt.Sprintf("%s-%s-%s", "CNNVD-202110-072", "linux-tools-4.15.0-64", "4.15.0-64.73")), convey.ShouldEqual, 490865440)
	})
	convey.Convey("TestGenerateUUID", t, func() {
		convey.So(GenerateUUID(fmt.Sprintf("%s-%s-%s", "CNNVD-201707-867", "libk5crypto3", "1.12+dfsg-2ubuntu5.1")), convey.ShouldEqual, 490865440)
	})

}

func TestGenerateUUID64(t *testing.T) {
	convey.Convey("TestGenerateUUID", t, func() {
		convey.So(GenerateUUID64(fmt.Sprintf("%s-%s-%s", "CNNVD-201909-562", "curl", "7.61.1-r1")), convey.ShouldEqual, uint64(3535174093082062355))
	})
}
