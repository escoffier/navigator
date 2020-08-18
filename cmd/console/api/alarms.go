package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/go-chi/chi"

	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type alarmAlertSource struct {
	Name string `json:"name"`
	Key  int    `json:"key"`
}

type alarmVulnerabilityTagItemData struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
	Type  int    `json:"type"`
}

type alarmAlertItemData struct {
	Key       string           `json:"key"`
	Owner     string           `json:"owner"`
	OwnerID   string           `json:"ownerId"`
	Category  int              `json:"category"`
	Severity  int              `json:"severity"`
	Title     string           `json:"title"`
	Status    int              `json:"status"`
	UpdatedAt time.Time        `json:"updatedAt"`
	CreatedAt time.Time        `json:"createdAt"`
	Content   string           `json:"content"`
	TaskID    string           `json:"taskId"`
	Source    alarmAlertSource `json:"source"`
}

type alertVulnerabilityItemData struct {
	Key              int       `json:"key"`
	Name             string    `json:"name"`
	Severity         int       `json:"severity"`
	Recent           int       `json:"recent"`
	Component        string    `json:"component"`
	UpdatedAt        time.Time `json:"updated"`
	Lnk              string    `json:"lnk"`
	Solved           bool      `json:"solved"`
	InProd           bool      `json:"inProduction"`
	NetworkExploit   bool      `json:"networkExploitable"`
	HostPrivilege    bool      `json:"hostPrivilege"`
	CriticalRecent   bool      `json:"criticalRecent"`
	Desc             string    `json:"description"`
	AffectImages     []int     `json:"affectImages"`
	AffectContainers []int     `json:"affectContainers"`
	AffectHosts      []int     `json:"affectHosts"`
	CVSS2            float64   `json:"cvss2"`
	CVSS3            float64   `json:"cvss3"`
	EvalScore        int       `json:"evalScore"`
}

type reportItemData struct {
	Key      int       `json:"int"`
	Name     string    `json:"name"`
	Severity int       `json:"severity"`
	Total    int       `json:"total"`
	Critical int       `json:"critical"`
	Finished time.Time `json:"finished"`
	Created  time.Time `json:"created"`
}

type hostItemData struct {
	Name string `json:"name"`
	Lnk  string `json:"lnk,omitempty"`
}

type reportProblemItemData struct {
	Key            int            `json:"int"`
	Name           string         `json:"name"`
	Desc           string         `json:"description"`
	Result         int            `json:"result"`
	Critical       int            `json:"critical"`
	ComplianceHost []hostItemData `json:"complianceHost"`
	Handle         string         `json:"handle"`
}

type alarmsAlerts []alarmAlertItemData

type alarmsVulnerabilities struct {
	Vulnerabilities []alertVulnerabilityItemData `json:"list"`
}

type alarmsReports struct {
	Reports []reportItemData `json:"list"`
}

type alarmsReportsProblems struct {
	Problems []reportProblemItemData `json:"list"`
}

type alarmsVulnsTags struct {
	Tags []alarmVulnerabilityTagItemData `json:"list"`
}

func (api *api) restAlarms() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/alerts", alertsAlarms)
		r.Get("/reports", reportsAlarms)
		r.Get("/reports/problems", reportsProblemsAlarms)
		r.Get("/vulnerabilities", vulnabilitiesAlarms)
		r.Get("/vulnerabilities/tags", vulnsTagsAlarms)
	}
}

// @Summary Alarm Vulnerabilities API
// @Description Get all Vulnerabilities
// @ID v1-alarms-vulnerabilities
// @Produce json
// @Success 200 {object} api.alarmsVulnerabilities "Vulnerability Alarms Data"
// @Router /api/v1/alarms/vulnerabilities [get]
func vulnabilitiesAlarms(w http.ResponseWriter, r *http.Request) {
	d := alarmsVulnerabilities{
		[]alertVulnerabilityItemData{
			{1, "CVE-2019-0001",
				rand.Intn(4), rand.Intn(2),
				"ubuntu: 16.04/apt:1.0",
				time.Now(), "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
				false, true, false, true, true,
				"此漏洞为cve-2019-0002", []int{1, 2, 3}, []int{1, 2, 3},
				[]int{1, 2, 3}, rand.Float64() * 10, rand.Float64() * 10, rand.Intn(100),
			},
			{2, "CVE-2019-0002",
				rand.Intn(4), rand.Intn(2),
				"ubuntu: 16.04/apt:1.0",
				time.Now(), "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
				false, true, false, true, true,
				"此漏洞为cve-2019-0002", []int{1, 2, 3}, []int{1, 2, 3},
				[]int{1, 2, 3}, rand.Float64() * 10, rand.Float64() * 10, rand.Intn(100),
			},
			{3, "CVE-2019-0003",
				rand.Intn(4), rand.Intn(2),
				"ubuntu: 16.04/apt:1.0",
				time.Now(), "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
				false, true, false, true, true,
				"此漏洞为cve-2019-0002", []int{1, 2, 3}, []int{1, 2, 3},
				[]int{1, 2, 3}, rand.Float64() * 10, rand.Float64() * 10, rand.Intn(100),
			},
			{4, "CVE-2019-0004",
				rand.Intn(4), rand.Intn(2),
				"ubuntu: 16.04/apt:1.0",
				time.Now(), "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
				false, true, false, true, true,
				"此漏洞为cve-2019-0002", []int{1, 2, 3}, []int{1, 2, 3},
				[]int{1, 2, 3}, rand.Float64() * 10, rand.Float64() * 10, rand.Intn(100),
			},
			{5, "CVE-2019-0005",
				rand.Intn(4), rand.Intn(2),
				"ubuntu: 16.04/apt:1.0",
				time.Now(), "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
				false, true, false, true, true,
				"此漏洞为cve-2019-0002", []int{1, 2, 3}, []int{1, 2, 3},
				[]int{1, 2, 3}, rand.Float64() * 10, rand.Float64() * 10, rand.Intn(100),
			},
		},
	}
	response.Ok(w, d)
}

// @Summary Alarm Alerts API
// @Description Get all Alerts
// @ID v1-alarms-alerts
// @Produce json
// @Success 200 {object} api.alarmsAlerts "Alerts Alarms Data"
// @Router /api/v1/alarms/alerts [get]
func alertsAlarms(w http.ResponseWriter, r *http.Request) {
	d := alarmsAlerts{
		{
			"alert_1", "老板", "00000001",
			rand.Intn(6), rand.Intn(4),
			"告警1", rand.Intn(4), time.Now(),
			time.Now(),
			"网络产生异常流量, 源为 10.5.140.10， 目的地为 10.5.142.1, 扫描流量",
			"HandleTask1",
			alarmAlertSource{"容器1", rand.Intn(5)},
		},
		{
			"alert_2", "管理员", "00000002",
			rand.Intn(6), rand.Intn(4),
			"告警1", rand.Intn(4), time.Now(),
			time.Now(),
			"网络产生异常流量, 源为 10.5.140.10， 目的地为 10.5.142.2, 扫描流量",
			"HandleTask1",
			alarmAlertSource{"容器2", rand.Intn(5)},
		},
		{
			"alert_3", "周润发", "00000003",
			rand.Intn(6), rand.Intn(4),
			"告警1", rand.Intn(4), time.Now(),
			time.Now(),
			"网络产生异常流量, 源为 10.5.140.10， 目的地为 10.5.142.3, 扫描流量",
			"HandleTask1",
			alarmAlertSource{"容器3", rand.Intn(5)},
		},
		{
			"alert_4", "周星星", "00000004",
			rand.Intn(6), rand.Intn(4),
			"告警1", rand.Intn(4), time.Now(),
			time.Now(),
			"网络产生异常流量, 源为 10.5.140.10， 目的地为 10.5.142.4, 扫描流量",
			"HandleTask1",
			alarmAlertSource{"容器4", rand.Intn(5)},
		},
		{
			"alert_5", "周星星", "00000004",
			rand.Intn(6), rand.Intn(4),
			"告警1", rand.Intn(4), time.Now(),
			time.Now(),
			"网络产生异常流量, 源为 10.5.140.10， 目的地为 10.5.142.5, 扫描流量",
			"HandleTask1",
			alarmAlertSource{"容器5	", rand.Intn(5)},
		},
	}

	response.Ok(w, d)
}

// @Summary Alarm Reports API
// @Description Get all Reports
// @ID v1-alarms-reports
// @Produce json
// @Success 200 {object} api.alarmsReports "Reports Alarms Data"
// @Router /api/v1/alarms/reports [get]
func reportsAlarms(w http.ResponseWriter, r *http.Request) {
	d := alarmsReports{
		Reports: []reportItemData{
			{
				1, "Kuberentes合规", rand.Intn(4),
				rand.Intn(10), rand.Intn(10),
				time.Now(), time.Now(),
			},
			{
				2, "docker 合规扫描", rand.Intn(4),
				rand.Intn(10), rand.Intn(10),
				time.Now(), time.Now(),
			},
			{
				3, "主机合规扫描", rand.Intn(4),
				rand.Intn(10), rand.Intn(10),
				time.Now(), time.Now(),
			},
			{
				4, "Kuberentes合规", rand.Intn(4),
				rand.Intn(10), rand.Intn(10),
				time.Now(), time.Now(),
			},
		},
	}
	response.Ok(w, d)
}

// @Summary Alarm Reports Problems API
// @Description Get all Problems in Reports
// @ID v1-alarms-reports-problems
// @Produce json
// @Success 200 {object} api.alarmsReportsProblems "Reports Problems Alarms Data"
// @Router /api/v1/alarms/reports/problems [get]
func reportsProblemsAlarms(w http.ResponseWriter, r *http.Request) {
	d := alarmsReportsProblems{
		Problems: []reportProblemItemData{
			{1, "docker 合规扫描",
				"确保Kubelet 配置 --allow-privileged 参数设置为 false (Scored)",
				0, rand.Intn(3), []hostItemData{
					{"主机0", "/detail/node/0"},
					{"主机1", "/detail/node/1"},
				},
				"If using a Kubelet config file, " +
					"edit the file to set authentication: x509: clientCAFile to\n" +
					"the location of the client CA file.\n" +
					"If using command line arguments,nedit the kubelet service file\n" +
					"$kubeletsvc on each worker node and\n" +
					"set the below parameter in KUBELET_AUTHZ_ARGS variable.\n" +
					"--client-ca-file=<path/to/client-ca-file>\n" +
					"Based on your system, restart the kubelet service. For example:\n" +
					"systemctl daemon-reload\nsystemctl restart kubelet.service",
			},
			{2, "主机合规扫描",
				"确保Kubelet 配置 --allow-privileged 参数设置为 false (Scored)",
				0, rand.Intn(3), []hostItemData{
					{"主机0", "/detail/node/0"},
					{"主机1", "/detail/node/1"},
				},
				"If using a Kubelet config file, " +
					"edit the file to set authentication: x509: clientCAFile to\n" +
					"the location of the client CA file.\n" +
					"If using command line arguments,nedit the kubelet service file\n" +
					"$kubeletsvc on each worker node and\n" +
					"set the below parameter in KUBELET_AUTHZ_ARGS variable.\n" +
					"--client-ca-file=<path/to/client-ca-file>\n" +
					"Based on your system, restart the kubelet service. For example:\n" +
					"systemctl daemon-reload\nsystemctl restart kubelet.service",
			},
			{3, "Kuberentes合规",
				"确保Kubelet 配置 --allow-privileged 参数设置为 false (Scored)",
				0, rand.Intn(3), []hostItemData{
					{"主机0", "/detail/node/0"},
					{"主机1", "/detail/node/1"},
				},
				"If using a Kubelet config file, " +
					"edit the file to set authentication: x509: clientCAFile to\n" +
					"the location of the client CA file.\n" +
					"If using command line arguments,nedit the kubelet service file\n" +
					"$kubeletsvc on each worker node and\n" +
					"set the below parameter in KUBELET_AUTHZ_ARGS variable.\n" +
					"--client-ca-file=<path/to/client-ca-file>\n" +
					"Based on your system, restart the kubelet service. For example:\n" +
					"systemctl daemon-reload\nsystemctl restart kubelet.service",
			},
			{4, "docker 合规扫描",
				"确保Kubelet 配置 --allow-privileged 参数设置为 false (Scored)",
				0, rand.Intn(3), []hostItemData{
					{"主机0", "/detail/node/0"},
					{"主机1", "/detail/node/1"},
				},
				"If using a Kubelet config file, " +
					"edit the file to set authentication: x509: clientCAFile to\n" +
					"the location of the client CA file.\n" +
					"If using command line arguments,nedit the kubelet service file\n" +
					"$kubeletsvc on each worker node and\n" +
					"set the below parameter in KUBELET_AUTHZ_ARGS variable.\n" +
					"--client-ca-file=<path/to/client-ca-file>\n" +
					"Based on your system, restart the kubelet service. For example:\n" +
					"systemctl daemon-reload\nsystemctl restart kubelet.service",
			},
		},
	}
	response.Ok(w, d)
}

// @Summary Alarm Vulnerabilities Tags API
// @Description Get all Vulnerabilities Tags
// @ID v1-alarms-vulnerabilities-tags
// @Produce json
// @Success 200 {object} api.alarmsVulnsTags "Vulnerabilities Tags Alarms Data"
// @Router /api/v1/alarms/vulnerabilities/tags [get]
func vulnsTagsAlarms(w http.ResponseWriter, r *http.Request) {
	var items []alarmVulnerabilityTagItemData
	for i := 0; i < 100; i++ {
		items = append(items, alarmVulnerabilityTagItemData{
			fmt.Sprintf("CVE-2019-00%02d", i),
			rand.Intn(50) + 50,
			rand.Intn(2),
		})
	}

	d := alarmsVulnsTags{
		items,
	}
	response.Ok(w, d)
}
