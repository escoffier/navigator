package model

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Filter struct {
	PageSize  int64  `json:"page_size"`
	PageIndex int64  `json:"page_index"`
	SortBy    string `json:"sort_by"`
	SortFiled string `json:"sort_filed"`
	Offset    int64  `json:"offset"`
	Limit     int64  `json:"limit"`
}

func GetFilter(ctx *gin.Context) *Filter {
	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	sortBy := ctx.Query("sort_by")
	sortFiled := ctx.Query("sort_filed")

	filter := &Filter{PageSize: limit, Offset: offset, Limit: limit, SortBy: sortBy, SortFiled: sortFiled}
	filter = filter.SetDefault()
	return filter
}

// EmptyFilterForTheTotalQuery 查总数所用的Filter
func EmptyFilterForTheTotalQuery() *Filter {
	return &Filter{
		PageSize:  1,
		PageIndex: 1,
		Offset:    0,
	}
}

func (f *Filter) SetDefault() *Filter {
	if f == nil {
		return &Filter{
			PageSize:  math.MaxInt64,
			PageIndex: 1,
			Offset:    0,
		}
	}
	if f.SortBy != "" {
		f.SortBy = strings.ToLower(f.SortBy)
	} else {
		f.SortBy = "id"
	}

	if f.SortBy == "" || (f.SortBy != "desc" && f.SortBy != "asc") {
		f.SortBy = "desc"
	}

	if f.Offset == 0 {
		f.PageIndex = 1 // 取第一页
	}
	// 为了兼容,原来的逻辑传的是offset参数
	if f.Offset > 0 && f.PageIndex <= 0 && f.PageSize > 0 {
		f.PageIndex = f.Offset/f.PageSize + 1
	}
	// if f.PageSize <= 0 || f.PageSize > DefaultPageSize {
	// 	f.PageSize = math.MaxInt64
	// }
	if f.Offset <= 0 && f.PageSize > 0 && f.PageIndex > 0 {
		f.Offset = (f.PageIndex - 1) * f.PageSize
	}

	return f
}

func AddFilter(db *gorm.DB, filter *Filter) *gorm.DB {
	if filter != nil {
		if filter.PageIndex >= 1 && filter.PageSize > 0 {
			db = db.Offset(int((filter.PageIndex - 1) * filter.PageSize)).Limit(int(filter.PageSize))
		}

		if filter.SortFiled != "" && filter.SortBy != "" {
			db = db.Order(clause.OrderByColumn{Column: clause.Column{Name: filter.SortFiled}, Desc: strings.ToLower(filter.SortBy) == "desc"})
		}
	}
	// 这里如果是查全部，也给一个默认值，但是我们项目业务中有很多查全表数据的情况，所这里加这一项不合适
	// if filter == nil {
	// 	db = db.Limit(DefaultPageSize)
	// }
	return db
}

// 扫描配置
type ScanConfig struct {
	Href string `json:"href"`
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
