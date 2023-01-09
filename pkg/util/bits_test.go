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

	convey.Convey("TestSetBit0", t, func() {
		convey.So(ExistBit1(147525, 17), convey.ShouldEqual, true)
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

func TestCompareVersion(t *testing.T) {
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("", ""), convey.ShouldEqual, 0)
	})
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("", "0.1"), convey.ShouldEqual, -1)
	})
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("0.1", ""), convey.ShouldEqual, 1)
	})
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("0", ""), convey.ShouldEqual, 0)
	})
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("0", "0-hello"), convey.ShouldEqual, 0)
	})
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("2.12", "2.11-amd"), convey.ShouldEqual, 1)
	})
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("0.12", "2.11"), convey.ShouldEqual, -1)
	})
	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("2.12-amd", ""), convey.ShouldEqual, 1)
	})

	convey.Convey("TestCompareVersion", t, func() {
		convey.So(CompareVersion("0", "latest"), convey.ShouldEqual, 0)
	})
}
