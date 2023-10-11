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
		convey.So(SetBit1(uint64(0), 1), convey.ShouldEqual, 2)
	})
	convey.Convey("TestSetBit0", t, func() {
		convey.So(ExistBit1(uint64(8589938688), uint64(12)), convey.ShouldEqual, true)
		convey.So(ExistBit1(uint64(9223372045294241088), uint64(29)), convey.ShouldEqual, true)
		convey.So(ExistBit1(uint64(9223372045294241088), uint64(30)), convey.ShouldEqual, true)
		convey.So(ExistBit1(uint64(9223372045294241088), uint64(31)), convey.ShouldEqual, true)
		// convey.So(ExistBit1(uint64(8589934592), uint64(36)), convey.ShouldEqual, true)
		// convey.So(ExistBit1(uint64(8589934592), uint64(35)), convey.ShouldEqual, true)
		// convey.So(ExistBit1(uint64(8589934592), uint64(34)), convey.ShouldEqual, true)
		convey.So(ExistBit1(uint64(8589934592), uint64(33)), convey.ShouldEqual, true)
	})

}

func TestSetBit1(t *testing.T) {
	convey.Convey("TestSetBit1", t, func() {
		convey.So(SetBit1(1<<3, 3), convey.ShouldEqual, 1<<3)
	})
	convey.Convey("TestSetBit1", t, func() {
		convey.So(SetBit1(1<<20, 0), convey.ShouldEqual, 1<<20+1)
	})
	convey.Convey("TestSetBit1", t, func() {
		convey.So(SetBit1(1<<34, 0), convey.ShouldEqual, 1<<34+1)
	})

	convey.Convey("TestExit", t, func() {
		convey.So(ExistBit1(uint64(9223372045285329535), uint64(19)), convey.ShouldEqual, false)
	})

	convey.Convey("TestExit", t, func() {
		convey.So(ExistBit1(uint64(9223372045285329535), uint64(18)), convey.ShouldEqual, false)
	})

	convey.Convey("TestExit", t, func() {
		convey.So(ExistBit1(uint64(110), uint64(1)), convey.ShouldEqual, true)
	})

	convey.Convey("TestSetBit1", t, func() {
		var flag uint64
		flag = SetBit1(flag, 28)
		flag = SetBit1(flag, 29)
		flag = SetBit1(flag, 30)
		flag = SetBit1(flag, 31)
		flag = SetBit1(flag, 32)

		convey.So(flag, convey.ShouldEqual, 8321499136)
	})

	convey.Convey("TestSetBit1", t, func() {
		convey.So(ExistBit1(uint64(9223372036972743236), 28), convey.ShouldEqual, false)
		convey.So(ExistBit1(uint64(9223372036972743236), 29), convey.ShouldEqual, false)
		convey.So(ExistBit1(uint64(9223372036972743236), 30), convey.ShouldEqual, false)
		convey.So(ExistBit1(uint64(9223372036972743236), 31), convey.ShouldEqual, false)
		convey.So(ExistBit1(uint64(9223372036972743236), 32), convey.ShouldEqual, false)
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
