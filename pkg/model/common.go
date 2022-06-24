package model

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

type Filter struct {
	// 如果只有一项排序可以写在SortBy和SortFiled这两个字段中，
	SortBy    string `json:"sort_by"`
	SortFiled string `json:"sort_filed"`

	// 如果是多行或指义的排列，就写入OrderByColumns字段中
	OrderByColumns []clause.OrderByColumn

	Offset int64 `json:"offset"`
	Limit  int64 `json:"limit"`
}

func (f *Filter) AddSortCreatedAt() {
	f.SortFiled = "created_at"
}

func (f *Filter) AddSortDesc() {
	f.SortBy = consts.SortByDesc
}

func (f *Filter) AddSortAsc() {
	f.SortBy = consts.SortByAsc
}

func GetFilter(ctx *gin.Context) *Filter {
	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	sortBy := ctx.Query("sort_by")
	sortFiled := ctx.Query("sort_filed")
	if limit > 200 {
		limit = 200
	}
	if offset <= 0 {
		offset = 0
	}

	filter := &Filter{Offset: offset, Limit: limit, SortBy: sortBy, SortFiled: sortFiled}
	filter.OrderByColumns = make([]clause.OrderByColumn, 0)
	filter = filter.SetDefault()
	return filter
}

func GetFilterWithDefaultValue(ctx *gin.Context) *Filter {
	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	sortBy := ctx.Query("sort_by")
	sortFiled := ctx.Query("sort_filed")
	if limit > consts.DefaultLimit || limit <= 0 {
		limit = consts.DefaultLimit
	}
	if offset <= 0 {
		offset = consts.DefaultOffset
	}

	filter := &Filter{Offset: offset, Limit: limit, SortBy: sortBy, SortFiled: sortFiled}
	filter.OrderByColumns = make([]clause.OrderByColumn, 0)
	filter = filter.SetDefault()
	return filter
}

// EmptyFilterForTheTotalQuery 查总数所用的Filter
func EmptyFilterForTheTotalQuery() *Filter {
	return &Filter{
		Offset:    0,
		Limit:     math.MaxInt64,
		SortBy:    "desc",
		SortFiled: "id",
	}
}

func (f *Filter) SetDefault() *Filter {
	if f == nil {
		return &Filter{
			Offset:    0,
			Limit:     math.MaxInt64,
			SortBy:    "desc",
			SortFiled: "id",
		}
	}
	if f.SortBy != "" {
		f.SortBy = strings.ToLower(f.SortBy)
	} else {
		f.SortBy = "desc"
	}

	if f.SortBy == "" || (f.SortBy != "desc" && f.SortBy != "asc") {
		f.SortBy = "desc"
	}

	if f.Offset <= 0 {
		f.Offset = 0 // 取第一页
	}
	if f.Limit <= 0 {
		f.Limit = math.MaxInt64 // 没传就表示取全部，这里赋一个最大值
	}
	return f
}

func (f *Filter) DeepCopy() *Filter {

	if f == nil {
		return nil
	}
	res := Filter{
		SortBy:    f.SortBy,
		SortFiled: f.SortFiled,
		Offset:    f.Offset,
		Limit:     f.Limit,
	}
	return &res
}

func AddFilter(db *gorm.DB, filter *Filter) *gorm.DB {
	if filter != nil {
		if filter.Offset >= 0 && filter.Limit > 0 {
			db = db.Offset(int(filter.Offset)).Limit(int(filter.Limit))
		}
		if filter.SortFiled != "" && filter.SortBy != "" {
			db = db.Order(clause.OrderByColumn{Column: clause.Column{Name: filter.SortFiled}, Desc: strings.ToLower(filter.SortBy) == "desc"})
		}

		if filter.OrderByColumns != nil {
			for i := range filter.OrderByColumns {
				db = db.Order(filter.OrderByColumns[i])
			}
		}
	}
	// 这里如果是查全部，也给一个默认值，但是我们项目业务中有很多查全表数据的情况，所这里加这一项不合适
	// if filter == nil {
	// 	db = db.Limit(DefaultPageSize)
	// }
	return db
}

// 扫描状态
type ScanStatus struct {
	ScanAllStatus ScanAllStatus `json:"harborStatus"`
	IsAborted     bool          `json:"isAborted"` // if true, we are currently in the process of aborting harbor scan al

	EndTime    time.Time `json:"end_time"`
	ScanStatus string    `json:"scan_status"`
}

type ScanAllStatusMetrics struct {
	Error   int `json:"error"`
	Pending int `json:"pending"`
	Running int `json:"running"`
	Success int `json:"success"`
}

type ScanAllStatus struct {
	Completed int                  `json:"completed"`
	IsOngoing bool                 `json:"ongoing"`
	Requester string               `json:"requester"` // no idea what this is for
	Total     int                  `json:"total"`
	Metrics   ScanAllStatusMetrics `json:"metrics"`
}
