package util

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	json "github.com/json-iterator/go"
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

func TestJoinInt64Slice(t *testing.T) {
	convey.Convey("TestJoinInt64Slice ", t, func() {
		convey.So(JoinInt64Slice(nil, ","), convey.ShouldEqual, "")
		convey.So(JoinInt64Slice([]int64{}, ","), convey.ShouldEqual, "")
		convey.So(JoinInt64Slice([]int64{1, 2, 3}, ","), convey.ShouldEqual, "1,2,3")
	})
}

func TestDeDupArray(t *testing.T) {
	type ResourceApp struct {
		ID               uint32
		ClusterKey       string  `json:"clusterKey,omitempty"`
		Namespace        string  `json:"namespace,omitempty"`
		ResourceName     string  `json:"resourceName,omitempty"`
		AppType          *string `json:"appType,omitempty"`
		AppTargetName    *string `json:"appTargetName,omitempty"`
		AppTargetVersion *string `json:"appTargetVersion,omitempty"`
	}

	slice1 := []*ResourceApp{
		{
			ClusterKey:   "key1",
			Namespace:    "ns1",
			ResourceName: "res1",
		},
		{
			ClusterKey:   "key2",
			Namespace:    "ns1",
			ResourceName: "res1",
		},
		{
			ClusterKey:   "key1",
			Namespace:    "ns1",
			ResourceName: "res1",
		},
		{
			ClusterKey:   "key1",
			Namespace:    "ns2",
			ResourceName: "res1",
		},
		{
			ClusterKey:   "key1",
			Namespace:    "ns2",
			ResourceName: "res1",
		},
	}
	slice11 := DeDupArray(slice1, func(t *ResourceApp) string {
		return fmt.Sprintf("%s/%s/%s", t.ClusterKey, t.Namespace, t.ResourceName)
	})
	if len(slice11) != 3 {
		t.Errorf("DeDupArray() = %v, want %v", len(slice11), 3)
	}
}

func TestListDeduplicate(t *testing.T) {
	type args struct {
		list []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "1",
			args: args{list: []string{"1", "2", "1", "3", "1", "4"}},
			want: []string{"1", "2", "3", "4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ListDeduplicate(tt.args.list); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListDeduplicate() = %v, want %v", got, tt.want)
			}
		})
	}
}
