package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
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

func TestDeDuplicationUint64Slice(t *testing.T) {
	convey.Convey("Test de duplication ", t, func() {
		convey.So(DeDuplicationUint64Slice([]uint64{1, 2, 2, 3, 2, 3, 1}), convey.ShouldResemble, []uint64{1, 2, 3})
	})
	convey.Convey("Test empty ", t, func() {
		convey.So(DeDuplicationUint64Slice([]uint64{}), convey.ShouldResemble, []uint64{})
	})
	convey.Convey("Test nil ", t, func() {
		convey.So(DeDuplicationUint64Slice(nil), convey.ShouldNotBeNil)
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

func TestGenerateUUID64(t *testing.T) {
	convey.Convey("TestGenerateUUID", t, func() {
		convey.So(GenerateUUID64(fmt.Sprintf("%s-%s-%s", "CNNVD-201909-562", "curl", "7.61.1-r1")), convey.ShouldEqual, uint64(3535174093082062355))
	})
}

func TestIntersectionSetForInt64(t *testing.T) {
	convey.Convey("GetIntersectionSetForInt64 ", t, func() {
		convey.So(len(GetIntersectionSetForInt64([]int64{}, []int64{2, 3, 3})), convey.ShouldEqual, 0)
	})
	convey.Convey("GetIntersectionSetForInt64 ", t, func() {
		convey.So(len(GetIntersectionSetForInt64([]int64{2, 3, 3}, []int64{})), convey.ShouldEqual, 0)
	})

	convey.Convey("GetIntersectionSetForInt64 ", t, func() {
		convey.So(len(GetIntersectionSetForInt64([]int64{2, 3, 3}, []int64{1, 3, 4})), convey.ShouldEqual, 1)
	})
}

func TestUint64SliceToStringSlice(t *testing.T) {
	convey.Convey("Uint64SliceToStringSlice ", t, func() {
		convey.So(len(Uint64SliceToStringSlice([]uint64{2, 3, 3})), convey.ShouldEqual, 3)
	})
	convey.Convey("Uint64SliceToStringSlice ", t, func() {
		convey.So(len(Uint64SliceToStringSlice([]uint64{})), convey.ShouldEqual, 0)
	})

	convey.Convey("Uint64SliceToStringSlice ", t, func() {
		convey.So(Uint64SliceToStringSlice([]uint64{3, 4, 5})[0], convey.ShouldEqual, "3")
	})
}

func TestDeDuplicationStringSlice(t *testing.T) {
	convey.Convey("DeDuplicationStringSlice ", t, func() {
		convey.So(len(DeDuplicationStringSlice([]string{})), convey.ShouldEqual, 0)
	})
	convey.Convey("DeDuplicationStringSlice ", t, func() {
		convey.So(len(DeDuplicationStringSlice([]string{""})), convey.ShouldEqual, 1)
	})

	convey.Convey("DeDuplicationStringSlice ", t, func() {
		convey.So(len(DeDuplicationStringSlice([]string{"", "hello"})), convey.ShouldEqual, 2)
	})
	convey.Convey("DeDuplicationStringSlice ", t, func() {
		convey.So(len(DeDuplicationStringSlice([]string{"", "hello", "hello"})), convey.ShouldEqual, 2)
	})
}

func TestGetInt64SliceFromQuery(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		status := GetInt64SliceFromQuery(c, "status")
		c.JSON(http.StatusOK, status)
	})

	convey.Convey("GetInt64SliceFromQuery ", t, func() {

		w := performRequest(router, http.MethodGet, "/test?status=1,2,3,3,3")
		status := make([]int, 0, 10)
		bytes, err := ioutil.ReadAll(w.Body)
		convey.So(err, convey.ShouldBeNil)

		err = json.Unmarshal(bytes, &status)
		convey.So(err, convey.ShouldBeNil)
		convey.So(len(status), convey.ShouldEqual, 3)

	})

	convey.Convey("GetInt64SliceFromQuery empty ", t, func() {

		w := performRequest(router, http.MethodGet, "/test?status")
		status := make([]int, 0, 10)
		bytes, err := ioutil.ReadAll(w.Body)
		convey.So(err, convey.ShouldBeNil)

		err = json.Unmarshal(bytes, &status)
		convey.So(err, convey.ShouldBeNil)
		convey.So(len(status), convey.ShouldEqual, 0)

	})
}

func TestGetInt64FromQuery(t *testing.T) {
	router := gin.New()
	type res struct {
		Status int64 `json:"status"`
	}
	router.GET("/test", func(c *gin.Context) {
		status := GetInt64FromQuery(c, "status")

		c.JSON(http.StatusOK, res{Status: status})
	})

	convey.Convey("GetInt64SliceFromQuery ", t, func() {

		w := performRequest(router, http.MethodGet, "/test?status=1")
		status := &res{}

		bytes, err := ioutil.ReadAll(w.Body)
		convey.So(err, convey.ShouldBeNil)

		err = json.Unmarshal(bytes, &status)
		convey.So(err, convey.ShouldBeNil)
		convey.So(status.Status, convey.ShouldEqual, 1)

	})

	convey.Convey("GetInt64SliceFromQuery empty ", t, func() {

		w := performRequest(router, http.MethodGet, "/test")
		status := &res{}

		bytes, err := ioutil.ReadAll(w.Body)
		convey.So(err, convey.ShouldBeNil)

		err = json.Unmarshal(bytes, &status)
		convey.So(err, convey.ShouldBeNil)
		convey.So(status.Status, convey.ShouldEqual, 0)
	})
}

func performRequest(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
