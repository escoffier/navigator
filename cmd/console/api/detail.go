package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) restDetail() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/node", nodeDetail)
		r.Get("/container", containerDetail)
		r.Get("/service", api.serviceDetail())
		r.Get("/image", api.imageDetail())
		r.Get("/docker", dockerDetail)
		r.Get("/report", reportDetail)
	}
}

type detailNodeStatData struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	Owner   string    `json:"owner"`
	Status  int       `json:"status"`
	Tags    []string  `json:"tags"`
	OS      string    `json:"os"`
	Kernel  string    `json:"kernel"`
}

type detailServiceStatData struct {
	Name      string    `json:"name"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	Owner     string    `json:"owner"`
	Status    int       `json:"status"`
	Tags      []string  `json:"tags"`
	Pods      []int     `json:"pods"`
	Namespace string    `json:"namespace"`
}

type detailImageStatData struct {
	Name       string               `json:"name"`
	Created    time.Time            `json:"created"`
	Updated    time.Time            `json:"updated"`
	Owner      string               `json:"owner"`
	Status     int                  `json:"status"`
	Tags       []string             `json:"tags"`
	Image      detailContainerImage `json:"image"`
	Namespace  string               `json:"namespace"`
	Total      int                  `json:"total"`
	Containers []int                `json:"containers"`
	ID         string               `json:"id"`
	Digest     string               `json:"digest"`
	OS         string               `json:"os"`
}

type detailServiceInOutBoundData struct {
	MakerOffSet int       `json:"markerOffset"`
	Name        string    `json:"name"`
	Coordinates []float32 `json:"coordinates"`
}

type detailContainerImage struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type detailContainerStatData struct {
	Name      string               `json:"name"`
	Created   time.Time            `json:"created"`
	Updated   time.Time            `json:"updated"`
	Owner     string               `json:"owner"`
	Namespace string               `json:"namespace"`
	Image     detailContainerImage `json:"image"`
	Tags      []string             `json:"tags"`
	Status    int                  `json:"status"`
}

//type detailNodeLogItemData struct {
//	Key      string    `json:"key"`
//	Name     string    `json:"name"`
//	Desc     string    `json:"description"`
//	Severity int       `json:"severity"`
//	Created  time.Time `json:"created"`
//}

type detailImageVulnItemData struct {
	Key       string  `json:"key"`
	Name      string  `json:"name"`
	HasFix    bool    `json:"hasFix"`
	Fix       string  `json:"fix"`
	InWhite   bool    `json:"inwhite"`
	Layer     int     `json:"layer"`
	Severity  int     `json:"severity"`
	Component string  `json:"component"`
	Lnk       string  `json:"lnk"`
	Desc      string  `json:"description"`
	CVSS2     float64 `json:"cvss2"`
	CVSS3     float64 `json:"cvss3"`
}

type detailImageVulnData struct {
	Vulns []detailImageVulnItemData `json:"list"`
	Page  paginationData            `json:"pagination"`
}

type vtScoreData struct {
	Mal     int `json:"malicious"`
	Ben     int `json:"benign"`
	Unknown int `json:"unknown"`
}

type detailImageFileItemData struct {
	Key       string      `json:"key"`
	Name      string      `json:"name"`
	Cate      string      `json:"cate"`
	Sha       string      `json:"sha"`
	VtLnk     string      `json:"vt_lnk"`
	ScanDate  time.Time   `json:"scanDate"`
	InWhite   bool        `json:"inwhite"`
	Layer     int         `json:"layer"`
	Severity  int         `json:"severity"`
	Component string      `json:"component"`
	Desc      string      `json:"description"`
	VtScore   vtScoreData `json:"vt_score"`
}

type detailImageFileData struct {
	Files []detailImageFileItemData `json:"list"`
	Page  paginationData            `json:"pagination"`
}

type detailImageHistoryItemData struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Layer int    `json:"layer"`
	Desc  string `json:"description"`
	Sha   string `json:"sha"`
	Vulns int    `json:"vulnerabilities"`
}

type detailImagePackageItemData struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Source  string `json:"source"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Vulns   int    `json:"vulnerabilities"`
}

type detailImageHistoryData struct {
	History []detailImageHistoryItemData `json:"list"`
	Page    paginationData               `json:"pagination"`
}

type detailImagePackageData struct {
	Packages []detailImagePackageItemData `json:"list"`
	Page     paginationData               `json:"pagination"`
}

type detailNodeReportData struct {
	Key         string `json:"key"`
	Audit       string `json:"audit"`
	Object      string `json:"object"`
	Category    string `json:"category"`
	Test        string `json:"test"`
	Item        string `json:"item"`
	Remediation string `json:"remediation"`
	Result      int    `json:"result"`
}

type detailNodeContainerData struct {
	Key       int       `json:"key"`
	Name      string    `json:"name"`
	Title     string    `json:"title"`
	Owner     string    `json:"owner"`
	Image     string    `json:"image"`
	ImageID   int64     `json:"image_id"`
	Node      int       `json:"node"`
	Status    int       `json:"status"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedAt time.Time `json:"createdAt"`
}

type detailReportData struct {
	Name     string         `json:"name"`
	Entities []hostItemData `json:"entities"`
	Created  time.Time      `json:"created"`
	Finished time.Time      `json:"finsihed"`
	Owner    string         `json:"owner"`
	Status   int            `json:"status"`
	Total    int            `json:"total"`
	Critical int            `json:"critical"`
}

type detailNode struct {
	DetailNodeStat      detailNodeStatData        `json:"detail,omitempty"`
	DetailNodeReport    []detailNodeReportData    `json:"reports,omitempty"`
	DetailNodeLog       []detailNodeLogData       `json:"logs,omitempty"`
	DetailNodeContainer []detailNodeContainerData `json:"containers,omitempty"`
}

type detailContainer struct {
	DetailContainerStat detailContainerStatData `json:"detail"`
	DetailNodeReport    []detailNodeReportData  `json:"reports,omitempty"`
	DetailNodeLog       []detailNodeLogData     `json:"logs,omitempty"`
	DetailNodeAlerts    []detailNodeLogData     `json:"alerts,omitempty"`
}

type detailService struct {
	DetailServiceStat     detailServiceStatData         `json:"detail,omitempty"`
	DetailServiceInBound  []detailServiceInOutBoundData `json:"inbound,omitempty"`
	DetailServiceOutBound []detailServiceInOutBoundData `json:"outbound,omitempty"`
}

type detailNodeLogData struct {
	Key      string    `json:"key"`
	Name     string    `json:"name"`
	Desc     string    `json:"description"`
	Severity int       `json:"severity"`
	Created  time.Time `json:"created"`
}

type detailImage struct {
	DetailImageStat    detailImageStatData    `json:"details,omitempty"`
	DetailImageVulns   detailImageVulnData    `json:"vulns,omitempty"`
	DetailImageFiles   detailImageFileData    `json:"files,omitempty"`
	DetailImageHistory detailImageHistoryData `json:"commands,omitempty"`
	DetailImagePackage detailImagePackageData `json:"packages,omitempty"`
}

type detailDocker struct {
}

type detailReport struct {
	Detail detailReportData `json:"detail"`
}

func queryStat(ID int) detailNodeStatData {
	created, _ := time.Parse("2006-01-02T15:04:05", "2019-10-13T00:00:01")
	updated, _ := time.Parse("2006-01-02T15:04:05", "2019-10-13T00:00:01")

	return detailNodeStatData{
		Name:    fmt.Sprintf("节点 %d", ID),
		Created: created,
		Updated: updated,
		Owner:   "管理员",
		OS:      "Ubuntu: 18.04",
		Kernel:  "4.18",
		Tags:    []string{"DEVELOPMENT", "TENSORSECURITY.IO"},
		Status:  2,
	}
}

func queryContainerStat(ID int) detailContainerStatData {
	created, _ := time.Parse("2006-01-02T15:04:05", "2019-10-13T00:00:01")
	updated, _ := time.Parse("2006-01-02T15:04:05", "2019-10-13T00:00:01")

	return detailContainerStatData{
		Name:      fmt.Sprintf("容器 %d", ID),
		Created:   created,
		Updated:   updated,
		Owner:     "管理员",
		Namespace: "DEVELOPMENT",
		Image:     detailContainerImage{Key: "0", Name: "nginx:latest"},
		Tags:      []string{"DEVELOPMENT", "TENSORSECURITY.IO"},
		Status:    2,
	}
}

func queryContainers(ID int) detailNode {
	var containers []detailNodeContainerData

	for i := 0; i < 10; i++ {
		containers = append(containers, detailNodeContainerData{
			Name:      fmt.Sprintf("容器 %d", i),
			Title:     fmt.Sprintf("容器任务 %d", i),
			Owner:     "管理员",
			Image:     "nginx:latest",
			ImageID:   int64(i),
			Node:      i,
			Status:    rand.Intn(3),
			UpdatedAt: time.Now(),
			CreatedAt: time.Now(),
		})
	}

	d := detailNode{DetailNodeStat: queryStat(ID), DetailNodeContainer: containers}

	return d
}

func queryReports(ID int) detailNode {
	var reports []detailNodeReportData

	for i := 0; i < 10; i++ {
		reports = append(reports, detailNodeReportData{
			Key:      fmt.Sprintf("2.1.%d", i),
			Audit:    "ps -fC $kubeletbin",
			Object:   "kubelet",
			Category: "Kubebench主机合规",
			Test:     "确保Kubelet 配置 --allow-privileged 参数设置为 false (Scored)",
			Item:     "--allow-privileged",
			Remediation: "Edit the kubelet service file $kubeletsvc\n " +
				"on each worker node and set the below parameter in " +
				"KUBELET_SYSTEM_PODS_ARGS variable.\n --allow-privileged=false\n" +
				"Based on your system, restart the kubelet service. For example:\n" +
				"systemctl daemon-reload\n" +
				"systemctl restart kubelet.service",
			Result: rand.Intn(2),
		})
	}

	d := detailNode{DetailNodeStat: queryStat(ID), DetailNodeReport: reports}
	return d
}

func queryLogs(r *http.Request, ID int) detailNode {
	vulns, err := param.QueryInt(r, "vulns")
	if err != nil {
		vulns = 2
	}

	dateObj := time.Now()
	dateStr, err := param.QueryString(r, "date")
	if err == nil {
		dateObj, _ = time.Parse("2006-01-02", dateStr)
	}

	fmt.Println(dateObj)

	d := detailNode{DetailNodeStat: queryStat(ID)}
	d.DetailNodeLog = []detailNodeLogData{}

	for n := 0; n < vulns; n = n + 1 {
		tmp := detailNodeLogData{
			Name:     fmt.Sprintf("security events %d", n),
			Key:      fmt.Sprintf("event_%d", n),
			Desc:     fmt.Sprintf("这是一段描述 %d", n),
			Severity: rand.Intn(3),
			Created:  dateObj,
		}

		d.DetailNodeLog = append(d.DetailNodeLog, tmp)
	}

	return d
}

// @Summary Node Detail API
// @Description Get Node Detail Given ID
// @ID v1-detail-node
// @Produce json
// @Param ID query int true "detail ID"
// @Param query query string true "query type"
// @Param vulns query int false "number of logs"
// @Param date query string false "date of queried"
// @Success 200 {object} api.detailNode "Node Detail Data"
// @Router /api/v1/detail/node [get]
func nodeDetail(w http.ResponseWriter, r *http.Request) {
	ID, err := param.QueryInt(r, "id")
	if err != nil {
		response.InternalError(w, "node id cannot be empty")
	}

	queryType, err := param.QueryString(r, "query")
	if err != nil {
		// default query stat detail information
		queryType = "containers"
	}

	d := detailNode{}

	switch queryType {
	case "detail":
		d = detailNode{DetailNodeStat: queryStat(ID)}
	case "containers":
		d = queryContainers(ID)
	case "logs":
		d = queryLogs(r, ID)
	case "reports":
		d = queryReports(ID)
	}

	response.Ok(w, d)
}

// @Summary Container Detail API
// @Description Get Container Detail Given ID
// @ID v1-detail-container
// @Produce json
// @Param id query int true "container id"
// @Param query query string true "query type"
// @Success 200 {object} api.detailContainer "Container Detail Data"
// @Router /api/v1/detail/container [get]
func containerDetail(w http.ResponseWriter, r *http.Request) {
	ID, err := param.QueryInt(r, "id")
	if err != nil {
		response.InternalError(w, "node id cannot be empty")
	}

	queryType, err := param.QueryString(r, "query")
	if err != nil {
		// default query stat detail information
		queryType = "containers"
	}

	d := detailContainer{}
	stat := queryContainerStat(ID)

	switch queryType {
	case "detail":
		d.DetailContainerStat = stat
	case "logs":
		c := queryLogs(r, ID)
		d.DetailNodeLog = c.DetailNodeLog
		d.DetailContainerStat = stat
	case "reports":
		c := queryReports(ID)
		d.DetailNodeReport = c.DetailNodeReport
		d.DetailContainerStat = stat
	case "alerts":
		c := queryLogs(r, ID)
		d.DetailNodeAlerts = c.DetailNodeLog
		d.DetailContainerStat = stat
	}

	response.Ok(w, d)
}

// @Summary Service Detail API
// @Description Get Service Detail Given ID
// @ID v1-detail-service
// @Produce json
// @Param id query int true "service id"
// @Param query query string true "query type"
// @Success 200 {object} api.detailContainer "Container Detail Data"
// @Router /api/v1/detail/service [get]
// TODO:change to /api/v1/detail/service/{id}
func (api *api) serviceDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ID, err := param.QueryString(r, "id")
		if err != nil {
			response.InternalError(w, "service id cannot be empty")
			return
		}

		queryType, err := param.QueryString(r, "query")
		if err != nil {
			// default query stat detail information
			queryType = "containers"
		}
		findFilter := bson.M{"key": ID}
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		pickField := bson.D{{Key: "_id", Value: 0}, {Key: "details", Value: 1}}
		selectFilter := options.FindOne().SetProjection(pickField)
		queryResult := api.mongodb.Collection(clusterAssetCol).FindOne(ctx, findFilter, selectFilter)
		if queryResult.Err() != nil {
			response.Bad(w, fmt.Sprintf("MongoDB: %s", queryResult.Err()))
			return
		}

		m := make(map[string]interface{})
		err = queryResult.Decode(&m)
		if err != nil {
			response.Bad(w, fmt.Sprintf("MongoDB: %s", err))
			return
		}

		d := detailService{}

		detailServiceRawData, err := bson.Marshal(m["details"])
		if err != nil {
			response.Bad(w, fmt.Sprintf("BSON Marshal: %s", err))
			return
		}
		var detailData detailServiceStatData
		err = bson.Unmarshal(detailServiceRawData, &detailData)
		if err != nil {
			fmt.Println(err)
		}
		d.DetailServiceStat = detailData

		switch queryType {
		case "inbound":
			var inData []detailServiceInOutBoundData
			inboundRawData, err := bson.Marshal(m["inbound"])
			if err != nil {
				response.Bad(w, fmt.Sprintf("BSON Marshal: %s", err))
				return
			}
			err = bson.Unmarshal(inboundRawData, &inData)
			if err != nil {
				fmt.Println(err)
			}
			d.DetailServiceOutBound = inData
		case "outbound":
			var outData []detailServiceInOutBoundData
			inboundRawData, err := bson.Marshal(m["outbound"])
			if err != nil {
				response.Bad(w, fmt.Sprintf("BSON Marshal: %s", err))
				return
			}
			err = bson.Unmarshal(inboundRawData, &outData)
			if err != nil {
				fmt.Println(err)
			}
			d.DetailServiceOutBound = outData
		}

		// created, _ := time.Parse("2006-01-02 15:04:05", "2019-10-13 00:00:01")
		// updated, _ := time.Parse("2006-01-02 15:04:05", "2019-10-14 00:00:01")
		// stat := detailServiceStatData{
		// 	Name:      fmt.Sprintf("微服务%d", ID),
		// 	Pods:      []int{0, 1, 2, 3},
		// 	Owner:     "管理员",
		// 	Created:   created,
		// 	Updated:   updated,
		// 	Status:    rand.Intn(3),
		// 	Namespace: "DEVELOPMENT",
		// 	Tags:      []string{"DEVELOPMENT", "TENSORSECURITY.io"},
		// }

		// switch queryType {
		// case "detail":
		// 	d.DetailServiceStat = stat
		// case "inbound":
		// 	d.DetailServiceStat = stat
		// 	d.DetailServiceInBound = []detailServiceInOutBoundData{
		// 		{-15, "34.1.1.6", []float32{-66.9036, 10.4806}},
		// 		{-15, "34.1.1.7", []float32{-77.0428, -12.0464}},
		// 		{-15, "34.1.1.8", []float32{-68.1193, -16.4897}},
		// 	}
		// case "outbound":
		// 	d.DetailServiceStat = stat
		// 	d.DetailServiceOutBound = []detailServiceInOutBoundData{
		// 		{25, "34.1.1.1", []float32{-47.8825, -15.7942}},
		// 		{25, "34.1.1.2", []float32{-70.6693, -33.4489}},
		// 		{25, "34.1.1.3", []float32{31.230398, 121.47370999999998}},
		// 		{25, "34.1.1.4", []float32{-74.0721, 4.711}},
		// 	}
		// }

		response.Ok(w, d)
	}
}

// @Summary Image Detail API
// @Description Get Image Detail Given ID
// @ID v1-detail-image
// @Produce json
// @Param id query string true "image id"
// @Param query query string true "query type"
// @Success 200 {object} api.detailImage "Image Detail Data"
// @Router /api/v1/detail/image [get]
// TODO:change to /api/v1/detail/image/{id}
func (api *api) imageDetail() http.HandlerFunc {
	type detailImageReceive struct {
		DetailImageStat    detailImageStatData          `json:"details,omitempty" bson:"details"`
		DetailImageVulns   []detailImageVulnItemData    `json:"vulns,omitempty" bson:"vulns"`
		DetailImageFiles   []detailImageFileItemData    `json:"files,omitempty" bson:"files"`
		DetailImageHistory []detailImageHistoryItemData `json:"commands,omitempty" bson:"commands"`
		DetailImagePackage []detailImagePackageItemData `json:"packages,omitempty" bson:"packages"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ID, err := param.QueryString(r, "id")
		if err != nil {
			response.InternalError(w, "node id cannot be empty")
			return
		}

		queryType, err := param.QueryString(r, "query")
		if err != nil {
			// default query stat detail information
			queryType = "details"
		}

		findFilter := bson.M{"key": ID}
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		d := detailImage{}
		// fieldKey := fmt.Sprintf("details.%s", queryType)
		// selectFilter := options.FindOne().SetProjection(bson.M{"_id": 0, fieldKey: 1})
		selectFilter := options.FindOne().SetProjection(bson.M{"_id": 0, "details": 1})
		queryResult := api.mongodb.Collection(imageAssetCol).FindOne(ctx, findFilter, selectFilter)

		if queryResult.Err() != nil {
			response.Bad(w, fmt.Sprintf("MongoDB: %s", queryResult.Err()))
			return
		}

		m := make(map[string]interface{})
		err = queryResult.Decode(&m)
		if err != nil {
			response.Bad(w, fmt.Sprintf("MongoDB: %s", err))
			return
		}

		mtwo := make(map[string]interface{})
		RawData, err := bson.Marshal(m["details"])
		if err != nil {
			response.Bad(w, fmt.Sprintf("BSON Marshal: %s", err))
			return
		}
		err = bson.Unmarshal(RawData, &mtwo)
		if err != nil {
			response.Bad(w, fmt.Sprintf("BSON Marshal: %s", err))
			return
		}

		dtwo := detailImageReceive{}
		err = bson.Unmarshal(RawData, &dtwo)
		if err != nil {
			response.Bad(w, fmt.Sprintf("Decode error: %s", err))
			return
		}

		switch queryType {
		case "details":
			d.DetailImageStat = dtwo.DetailImageStat
		case "vulns":
			items := dtwo.DetailImageVulns
			d.DetailImageVulns = detailImageVulnData{items, paginationData{}}
		case "files":
			items := dtwo.DetailImageFiles
			d.DetailImageFiles = detailImageFileData{items, paginationData{}}
		case "commands":
			items := dtwo.DetailImageHistory
			d.DetailImageHistory = detailImageHistoryData{items, paginationData{}}
		case "packages":
			items := dtwo.DetailImagePackage
			d.DetailImagePackage = detailImagePackageData{items, paginationData{}}
		}
		/**
		 * POC part
		switch queryType {
		case "detail":
			stat := detailImageStatData{
				Name:       fmt.Sprintf("镜像%d", ID),
				Created:    time.Now(),
				Updated:    time.Now(),
				Owner:      "管理员",
				Status:     rand.Intn(3),
				Tags:       []string{"Development", "TENSORSECURITY.io"},
				Image:      detailContainerImage{"100", "image1"},
				Namespace:  "dockerhub.com",
				Total:      rand.Intn(15),
				Digest:     "sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663",
				ID:         "sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663",
				Containers: []int{1, 2, 3},
				OS:         "Debian GNU/Linux 9 (stretch)",
			}
			d.DetailImageStat = stat
		case "vulns":
			items := []detailImageVulnItemData{
				{
					"cve_0", "CVE-2019-001", false, "网络流量检测签名",
					false, 1, 0, "cni-0.7.4",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					rand.Float64() * 10, rand.Float64() * 10,
				},
				{
					"cve_1", "CVE-2019-002", true, "自动更新软件包",
					true, 1, 0, "cni-0.7.4",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					rand.Float64() * 10, rand.Float64() * 10,
				},

				{
					"cve_2", "CVE-2019-003", false, "网络流量检测签名",
					false, 1, 0, "cni-0.7.4",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					rand.Float64() * 10, rand.Float64() * 10,
				},
				{
					"cve_3", "CVE-2019-004", true, "自动更新软件包",
					false, 1, 0, "cni-0.7.4",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					rand.Float64() * 10, rand.Float64() * 10,
				},
			}

			d.DetailImageVulns = detailImageVulnData{items, paginationData{}}
		case "files":
			items := []detailImageFileItemData{
				{
					"file_1", "file_001", "elf",
					"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
					"https://www.virustotal.com/gui/file/" +
						"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					time.Now(), false, 1, 0,
					"/usr/local/bin/exec",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					vtScoreData{40, 10, 2},
				},
				{
					"file_2", "file_002", "elf",
					"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
					"https://www.virustotal.com/gui/file/" +
						"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					time.Now(), true, 2, 2,
					"/usr/local/bin/exec",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					vtScoreData{40, 10, 2},
				},
				{
					"file_3", "file_003", "elf",
					"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
					"https://www.virustotal.com/gui/file/" +
						"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					time.Now(), true, 1, 1,
					"/usr/local/bin/exec",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					vtScoreData{40, 10, 2},
				},
				{
					"file_4", "file_004", "elf",
					"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
					"https://www.virustotal.com/gui/file/" +
						"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					time.Now(), false, 1, 0,
					"/usr/local/bin/exec",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					vtScoreData{40, 10, 2},
				},
				{
					"file_5", "file_005", "elf",
					"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
					"https://www.virustotal.com/gui/file/" +
						"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					time.Now(), false, 3, 2,
					"/usr/local/bin/exec",
					"Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4",
					vtScoreData{40, 10, 2},
				},
			}
			d.DetailImageFiles = detailImageFileData{items, paginationData{}}
		case "history":
			items := []detailImageHistoryItemData{
				{
					"command_0", "1", 1, "RUN apk add nginx",
					"sha:ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					5,
				},
				{
					"command_1", "2", 2, "COPY /workspace /user/src/",
					"sha:ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					5,
				},
				{
					"command_2", "3", 3, "RUN apk add vim",
					"sha:ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					5,
				},
				{
					"command_3", "4", 4, "RUN apk add curl",
					"sha:ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					5,
				},
				{
					"command_4", "5", 5, "RUN apk update",
					"sha:ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					5,
				},
				{
					"command_5", "6", 6, "FROM alpine:3.4",
					"sha:ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection",
					5,
				},
			}
			d.DetailImageHistory = detailImageHistoryData{items, paginationData{}}
		case "packages":
			items := []detailImagePackageItemData{
				{
					"package_0", "libacl1", "apt",
					"/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar",
					"2.2.52.-3", 4,
				},
				{
					"package_1", "libacl2", "apt",
					"/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar",
					"2.2.52.-3", 5,
				},
				{
					"package_2", "libacl3", "apt",
					"/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar",
					"2.2.52.-3", 6,
				},
				{
					"package_3", "libacl4", "apt",
					"/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar",
					"2.2.52.-3", 7,
				},
			}
			d.DetailImagePackage = detailImagePackageData{items, paginationData{}}
		}
		**/

		response.Ok(w, d)
	}
}

// @Summary Docker Detail API
// @Description Get Docker Detail Given ID
// @ID v1-detail-docker
// @Produce json
// @Param id query int true "docker id"
// @Param query query string true "query type"
// @Success 200 {object} api.detailDocker "Docker Detail Data"
// @Router /api/v1/detail/docker [get]
func dockerDetail(w http.ResponseWriter, r *http.Request) {
	//ID, err := param.QueryInt(r, "id")
	//if err != nil {
	//	response.InternalError(w, "node id cannot be empty")
	//}
	//
	//queryType, err := param.QueryString(r, "query")
	//if err != nil {
	//	// default query stat detail information
	//	queryType = "detail"
	//}

	d := detailDocker{}

	response.Ok(w, d)
}

// @Summary Compliance Report Detail API
// @Description Get Compliance Report Detail Given ID
// @ID v1-detail-report
// @Produce json
// @Param id query int true "report id"
// @Success 200 {object} api.detailReport "Report Detail Data"
// @Router /api/v1/detail/report [get]
func reportDetail(w http.ResponseWriter, r *http.Request) {
	ID, _ := param.QueryInt(r, "id")
	d := detailReport{
		Detail: detailReportData{fmt.Sprintf("Docker 扫描: %d", ID),
			[]hostItemData{{"主机0", "0"}, {"主机1", "1"}},
			time.Now(), time.Now(),
			"管理员", rand.Intn(2), 10, 8,
		},
	}

	response.Ok(w, d)
}
