package util

import (
	"math"
	"testing"

	"github.com/smartystreets/goconvey/convey"
)

func TestSetBit0(t *testing.T) {
	convey.Convey("TestSetBit0", t, func() {
		convey.So(SetBit0(1, 0), convey.ShouldEqual, 0)
	})
	convey.Convey("TestSetBit0", t, func() {
		convey.So(SetBit0(2, 0), convey.ShouldEqual, 2)
	})
	convey.Convey("TestSetBit0", t, func() {
		convey.So(SetBit0(0, 1), convey.ShouldEqual, 0)
	})

	convey.Convey("TestSetBit0", t, func() {
		convey.So(SetBit0(uint64(math.Pow(2, 20)), 20), convey.ShouldEqual, 0)
	})

	convey.Convey("TestSetBit0", t, func() {
		convey.So(SetBit0(uint64(1<<20), 20), convey.ShouldEqual, 0)
	})

}

func TestSetBit1(t *testing.T) {
	convey.Convey("TestSetBit1", t, func() {
		convey.So(SetBit1(1<<3, 3), convey.ShouldEqual, 1<<3)
	})
	convey.Convey("TestSetBit0", t, func() {
		convey.So(SetBit1(1<<20, 0), convey.ShouldEqual, 1<<20+1)
	})
	convey.Convey("TestSetBit0", t, func() {
		convey.So(SetBit1(1<<34, 0), convey.ShouldEqual, 1<<34+1)
	})
}
