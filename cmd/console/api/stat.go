package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi"

	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type noteData struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Logo        string    `json:"logo"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Member      string    `json:"member"`
	Href        string    `json:"href"`
	Cate        string    `json:"cate"`
	MemLink     string    `json:"memberLink"`
}

type notices []noteData
type nameStat struct {
	Name   string `json:"name"`
	Avatar string `json:"avatar,omitempty"`
	Link   string `json:"link,omitempty"`
}

type activity struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updatedAt"`
	User      nameStat  `json:"user"`
	Severity  nameStat  `json:"severity"`
	Group     nameStat  `json:"group"`
	Project   nameStat  `json:"project"`
	Template  string    `json:"template"`
}

type activitiesData []activity

type chartData struct {
	Radar radarDataArray `json:"radarData"`
}

type totalStat struct {
	Total  int `json:"total"`
	InUser int `json:"inUse"`
}

type radarData struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Value int    `json:"value"`
}

type radarDataArray []radarData

type dataStat struct {
	Containers totalStat `json:"containers"`
	Agents     totalStat `json:"agents"`
	Images     totalStat `json:"images"`
	Services   totalStat `json:"services"`
	Nodes      totalStat `json:"nodes"`
}

type xyAxisData struct {
	X string `json:"x"`
	Y int    `json:"y"`
}

type timeAxisData struct {
	X time.Time `json:"x"`
	Y int       `json:"y"`
}

type axisData struct {
	xyAxisData
	Category string `json:"category"`
}

type titleData struct {
	Title string `json:"title"`
	Value int    `json:"value"`
}

type overStat struct {
	StatData dataStat `json:"statData"`
}

type complianceItem struct {
	Name string  `json:"name"`
	Cvr  float32 `json:"cvr"`
}

type complianceData []complianceItem

type complianceChartItem struct {
	X  int64 `json:"x"`
	Y1 int   `json:"y1"`
	Y2 int   `json:"y2"`
}

type complianceChartData []complianceChartItem

type allTimeData struct {
	Critical []xyAxisData `json:"critical"`
	All      []xyAxisData `json:"all"`
}

type visitData []timeAxisData

type vulnerabilityItem struct {
	Index   int    `json:"index"`
	Keyword string `json:"keyword"`
	Count   int    `json:"count"`
	Range   int    `json:"range"`
	Status  int    `json:"status"`
}

type vulnerabilityData []vulnerabilityItem

type alertsDistDataHost []xyAxisData
type alertsDistDataContainer []xyAxisData
type alertsDistDataCluster []xyAxisData
type severityAlertData []axisData
type severityCheckData []axisData
type severityVulnerabilityData []axisData
type rankListData []titleData

type analysisData struct {
	Visit                 visitData                 `json:"visitData"`
	AllTime               allTimeData               `json:"allTimeData"`
	Vulnerability         vulnerabilityData         `json:"vulnerabilityData"`
	Compliance            complianceData            `json:"complianceData"`
	ComplianceChart       complianceChartData       `json:"complianceChartData"`
	AlertsDistHost        alertsDistDataHost        `json:"alertsDistDataHost"`
	AlertsDistContainer   alertsDistDataContainer   `json:"alertsDistDataContainer"`
	AlertsDistCluster     alertsDistDataCluster     `json:"alertsDistDataCluster"`
	SeverityAlert         severityAlertData         `json:"severityAlertData"`
	SeverityCheck         severityCheckData         `json:"severityCheckData"`
	SeverityVulnerability severityVulnerabilityData `json:"severityVulnerabilityData"`
	RankList              rankListData              `json:"rankingListData"`
}

func (api *api) restStat() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/notice", notice)
		r.Get("/activities", activities)
		r.Get("/chart", chartdata)
		r.Get("/stat", overallstat)
		r.Get("/analysis_chart", analysischart)
	}
}

// @Summary User API
// @Description Get current user
// @ID v1-stat-notice
// @Produce json
// @Success 200 {object} api.User "Current user"
// @Router /api/v1/overall/notice [get]
func notice(w http.ResponseWriter, r *http.Request) {
	response.Ok(w, response.WithItem(notices{
		{ID: "xxx1", Title: "周期性镜像扫描任务",
			Logo: "http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/" +
				"32/MetroUI-Apps-Winamp-icon.png",
			Description: "周期性扫描运行中的容器镜像并产生漏洞报告", UpdatedAt: time.Now(),
			Member: "上一份漏洞报告", Href: "/policy/general", Cate: "image", MemLink: "/alerts/overview"},
		{ID: "xxx2", Title: "周期性合规检测任务",
			Logo: "http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/" +
				"32/MetroUI-Folder-OS-Configure-Alt-icon.png",
			Description: "周期性对集群以及容器的配置进行扫描", UpdatedAt: time.Now(),
			Member: "上一份合规报告", Href: "/policy/general", Cate: "scap", MemLink: "/alerts/overview"},
		{ID: "xxx3", Title: "网络链接监测任务",
			Logo: "http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/" +
				"32/MetroUI-Apps-iCloud-icon.png",
			Description: "监测现在系统中网络链接状况", UpdatedAt: time.Now(),
			Member: "浏览网络链接", Href: "/policy/general", Cate: "monitor", MemLink: "/alerts/overview"},
		{ID: "xxx4", Title: "网络流量检测任务",
			Logo: "http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/" +
				"32/MetroUI-Google-Docs-icon.png",
			Description: "网络流量过滤并记录异常流量", UpdatedAt: time.Now(),
			Member: "浏览异常流量规则", Href: "/policy/general", Cate: "dpi", MemLink: "/alerts/overview"},
		{ID: "xxx5", Title: "文件系统监测任务",
			Logo: "http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/" +
				"32/MetroUI-Other-Task-icon.png",
			Description: "对平台下容器进行文件系统监测", UpdatedAt: time.Now(),
			Member: "浏览异常文件访问", Href: "/policy/general", Cate: "host", MemLink: "/alerts/overview"},
		{ID: "xxx6", Title: "异常进程监测任务",
			Logo: "http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/" +
				"32/MetroUI-Folder-OS-Security-Approved-icon.png",
			Description: "对平台下容器进行进程级监测", UpdatedAt: time.Now(),
			Member: "浏览容器中进程列表", Href: "/policy/general", Cate: "docker", MemLink: "/alerts/overview"},
	}))
}

// @Summary activity API
// @Description activity User
// @ID v1-stat-activities
// @Produce json
// @Success 200 {object} api.activitiesData "activitiesData of users"
// @Router /api/v1/overall/activities [get]
func activities(w http.ResponseWriter, r *http.Request) {
	response.Ok(w, response.WithItem(activitiesData{
		{
			ID:        "alert-1",
			UpdatedAt: time.Now(),
			User: nameStat{
				Name:   "container:nginx",
				Avatar: "http://icons.iconarchive.com/icons/custom-icon-design/flatastic-1/32/alert-icon.png",
			},
			Severity: nameStat{
				Name:   "中等",
				Avatar: "http://icons.iconarchive.com/icons/custom-icon-design/flatastic-1/32/alert-icon.png",
				Link:   "",
			},
			Group:    nameStat{Name: "主机监测任务", Link: ""},
			Project:  nameStat{Name: "[文件访问]", Link: ""},
			Template: "在 @{group} 中触发了 @{project}规则 警报级别[@{severity}]",
		}}))
}

// @Summary Chart Data API
// @Description chartData
// @ID v1-overall-chart
// @Produce json
// @Success 200 {object} api.chartData "Chart Data"
// @Router /api/v1/overall/chart [get]
func chartdata(w http.ResponseWriter, r *http.Request) {
	response.Ok(w, response.WithItem(chartData{Radar: radarDataArray{
		radarData{Name: "主机", Label: "漏洞数", Value: 10},
		radarData{Name: "主机", Label: "错误数", Value: 8},
		radarData{Name: "主机", Label: "动态警报数", Value: 4},
		radarData{Name: "主机", Label: "网络连接数", Value: 5},
		radarData{Name: "主机", Label: "服务数", Value: 7},
		radarData{Name: "容器", Label: "漏洞数", Value: 3},
		radarData{Name: "容器", Label: "错误数", Value: 9},
		radarData{Name: "容器", Label: "动态警报数", Value: 6},
		radarData{Name: "容器", Label: "网络连接数", Value: 3},
		radarData{Name: "容器", Label: "服务数", Value: 1},
		radarData{Name: "微服务集群", Label: "漏洞数", Value: 4},
		radarData{Name: "微服务集群", Label: "错误数", Value: 1},
		radarData{Name: "微服务集群", Label: "动态警报数", Value: 6},
		radarData{Name: "微服务集群", Label: "网络连接数", Value: 5},
		radarData{Name: "微服务集群", Label: "服务数", Value: 7},
	},
	}))
}

// @Summary Overall Stat API
// @Description Get Overall Stat
// @ID v1-overall-stat
// @Produce json
// @Success 200 {object} api.overStat "overStat Data"
// @Router /api/v1/overall/stat [get]
func overallstat(w http.ResponseWriter, r *http.Request) {
	response.Ok(w, response.WithItem(overStat{StatData: dataStat{
		Containers: totalStat{31, 0}, Agents: totalStat{2, 0},
		Images: totalStat{120, 34}, Services: totalStat{43, 0}, Nodes: totalStat{1, 0}}}))
}

// @Summary Overall Analysis Chart API
// @Description Get Overall Analysis Chart
// @ID v1-overall-analysis_chart
// @Produce json
// @Success 200 {object} api.analysisData "Analysis Chart Data"
// @Router /api/v1/overall/analysis_chart [get]
func analysischart(w http.ResponseWriter, r *http.Request) {
	jsonFile, err := os.Open("./testdata/stat_analysis.json")
	if err != nil {
		fmt.Println(err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var chart analysisData
	err = json.Unmarshal(byteValue, &chart)
	if err != nil {
		fmt.Println(err)
	}

	response.Ok(w, response.WithItem(chart))
}
