package riskexplorer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-redis/redis/v8"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	singleton *RiskExplorerService
	initOnce  sync.Once
)

const (
	maxCount = 200
	limit    = 100
)

func Init(scannerURL string, redisCli *redis.Client) error {
	initOnce.Do(func() {
		singleton = &RiskExplorerService{
			reporters:  make([]RiskTypeReporter, 0, 2),
			scannerURL: scannerURL,
		}
		// add more reporters here
		singleton.reporters = append(singleton.reporters, NewImageVulnsReporter(redisCli))
	})
	return nil
}

func Get(ctx context.Context) (*RiskExplorerService, bool) {
	return singleton, singleton != nil
}

type RiskTypeReporter interface {
	LoadSummary(ctx context.Context, assetsSummary []*NamespaceSummary) (TotalSummary, error)
	Name() string
}

type Summary struct {
	Count    int
	Severity Severity
	RiskType RiskTypeDesc
}
type TotalSummary interface {
	ResourceSummary(tx context.Context, clusterKey, namespace, resourceKind, resourceName string) (sums map[string]Summary, err error)
	Name() string
}

var (
	KeyImageVulns = RiskTypeDesc{
		Key:       "image-vulns",
		DisplayZh: "容器镜像漏洞",
		DisplayEn: "Container Image Vulnerabilities",
	}
	KeyImageViruses = RiskTypeDesc{
		Key:       "image-virus",
		DisplayZh: "容器镜像恶意文件",
		DisplayEn: "Container Image Viruses",
	}
	KeyImageWebshell = RiskTypeDesc{
		Key:       "image-webshell",
		DisplayZh: "容器镜像Webshell",
		DisplayEn: "Container Image Webshell",
	}

	riskTypes = map[string]RiskTypeDesc{
		KeyImageVulns.Key:    KeyImageVulns,
		KeyImageViruses.Key:  KeyImageViruses,
		KeyImageWebshell.Key: KeyImageWebshell,
	}
)

type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityNegligible
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func GetSeverityFromString(s string) Severity {
	s = strings.ToLower(s)
	switch s {
	case strings.ToLower(SeverityCritical.String()):
		return SeverityCritical
	case strings.ToLower(SeverityHigh.String()):
		return SeverityHigh
	case strings.ToLower(SeverityLow.String()):
		return SeverityLow
	case strings.ToLower(SeverityNegligible.String()):
		return SeverityNegligible
	default:
		return SeverityUnknown
	}
}
func (s Severity) String() string {
	switch s {
	case SeverityUnknown:
		return "Unknown"
	case SeverityNegligible:
		return "Negligible"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

type RiskExplorerService struct {
	scannerURL string
	reporters  []RiskTypeReporter
}

func (s *RiskExplorerService) WholeSummary(ctx context.Context, queryOpt *dal.ResContainersQueryOption) ([]*NamespaceSummary, error) {
	resSvc, _ := assetsSvc.GetResourcesService(ctx)
	totalCount := maxCount
	offset := 0
	failCnt := 0
	clusterKey, ok := queryOpt.GetClusterOption()
	if !ok {
		return nil, fmt.Errorf("invalid cluster key")
	}

	resQueryOpt := dal.ResourcesQuery()
	resMap, err := resSvc.GetResourceMap(ctx, resQueryOpt)
	if err != nil {
		return nil, err
	}

	nsMap := make(map[string]*NamespaceSummary, 10)
	for offset < totalCount {
		containers, tcount, err := resSvc.GetResourceContainers(ctx, queryOpt, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("query resource containers error. opt: %+v offset: %d limit: %d", queryOpt, offset, limit)
			failCnt++
			if failCnt == 3 {
				offset += limit
				failCnt = 0
			}
			continue
		}
		failCnt = 0
		totalCount = int(tcount)
		offset += len(containers)

		for _, container := range containers {
			nsItem, nsExist := nsMap[container.Namespace]
			if !nsExist {
				nsItem = new(NamespaceSummary)
				nsItem.ClusterKey = container.ClusterKey
				nsItem.Name = container.Namespace
				nsMap[container.Namespace] = nsItem
			}

			var svcItem *ResourceSummary
			for _, svc := range nsItem.ResourcesList {
				if container.ResourceName == svc.ResourceName && container.ResourceKind == svc.ResourceKind {
					svcItem = svc
					break
				}
			}
			if svcItem == nil {
				svcItem = new(ResourceSummary)
				svcItem.ResourceName = container.ResourceName
				svcItem.Namespace = container.Namespace
				svcItem.NodeType = "ownerReference"
				svcItem.ResourceKind = container.ResourceKind
				svcItem.ContainersList = make([]*ContainerSummary, 0, 2)
				svcItem.RiskTypes = make(map[string]RiskTypeDesc, 1)

				res, ok := resMap[dal.ResourceKey{
					ClusterKey:   clusterKey,
					Namespace:    container.Namespace,
					ResourceKind: container.ResourceKind,
					ResourceName: container.ResourceName,
				}]
				if ok {
					svcItem.Alias = res.Alias
					svcItem.Managers = res.Managers
					svcItem.Authority = res.Authority
				}
				nsItem.ResourcesList = append(nsItem.ResourcesList, svcItem)
			}

			var contSumm *ContainerSummary
			for _, cont := range svcItem.ContainersList {
				if cont.Name == container.Name {
					contSumm = cont
					break
				}
			}
			if contSumm == nil {
				contSumm = new(ContainerSummary)
				contSumm.Name = container.Name
				contSumm.ResourceName = container.ResourceName
				contSumm.Namespace = container.Namespace
				contSumm.RiskTypes = make(map[string]RiskTypeDesc, 10)
				contSumm.Image = container.Image
				svcItem.ContainersList = append(svcItem.ContainersList, contSumm)
				if container.AppType != nil && len(*container.AppType) > 0 {
					svcItem.AppType = *container.AppType
				}
				if container.AppTargetVersion != nil && len(*container.AppTargetVersion) > 0 {
					svcItem.AppTargetVersion = *container.AppTargetVersion
				}
				if container.AppTargetName != nil && len(*container.AppTargetName) > 0 {
					svcItem.AppTargetName = *container.AppTargetName
				}
			}
		}
	}

	nsSlice := make([]*NamespaceSummary, len(nsMap))
	i := 0
	for _, nsSumm := range nsMap {
		nsSlice[i] = nsSumm
		i++
	}
	summaries := make([]TotalSummary, 0, len(s.reporters))
	for _, reporter := range s.reporters {
		summary, lsErr := reporter.LoadSummary(ctx, nsSlice)
		if lsErr != nil {
			logging.GetLogger().Err(lsErr).Msgf("reporter %s error", reporter.Name())
			continue
		}
		summaries = append(summaries, summary)
	}
	for _, summ := range summaries {
		for _, nsSum := range nsSlice {
			for _, svcSum := range nsSum.ResourcesList {
				sums, err := summ.ResourceSummary(ctx, nsSum.ClusterKey, svcSum.Namespace, svcSum.ResourceKind, svcSum.ResourceName)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("%s-%s-%s-%s reporter %s summary err. summary: %v", nsSum.ClusterKey, svcSum.Namespace, svcSum.ResourceKind, svcSum.ResourceName, summ.Name(), sums)
					continue
				}
				for _, sum := range sums {
					if sum.Severity > SeverityNegligible {
						targetSumm := sum.RiskType
						targetSumm.Count = sum.Count
						svcSum.RiskTypes[sum.RiskType.Key] = targetSumm
					}
					if svcSum.RiskLevel < int(sum.Severity) {
						svcSum.RiskLevel = int(sum.Severity)
					}
					if sum.Severity > GetSeverityFromString(svcSum.FinalSeverity) {
						svcSum.FinalSeverity = sum.Severity.String()
					}
				}

			}
		}
	}

	return nsSlice, nil

}

func getImageVulnsRiskData(ctx context.Context, Vulns []model.VulnerabilityInfo, Sensitive []model.Sensitive) (json.RawMessage, bool) {
	imageVulns := ImageVulnsDetails{
		SensitiveFiles:  Sensitive,
		Vulnerabilities: Vulns,
	}

	for i, _ := range imageVulns.SensitiveFiles {
		if lang.Language(ctx) == lang.LanguageZH {
			description := imageVulns.SensitiveFiles[i].DescriptionZh
			imageVulns.SensitiveFiles[i].Description = description
		} else {
			description := imageVulns.SensitiveFiles[i].DescriptionEn
			imageVulns.SensitiveFiles[i].Description = description
		}
	}

	mar, err := json.Marshal(imageVulns)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("marshal vulns error. data: %+v", imageVulns)
		return nil, false
	}
	return mar, true
}

func getRepositoryAndTagFromImage(imageID string) (string, string) {
	splits := strings.SplitN(imageID, ":", 2)
	if len(splits) < 2 {
		return imageID, ""
	}
	return splits[0], splits[1]
}

type data struct {
	Item model.SimpleImageDetail `json:"item"`
}
type imageInfo struct {
	ApiVersion string `json:"apiVersion"`
	Data       data   `json:"data"`
}

func (s *RiskExplorerService) getImageScanDetail(ctx context.Context, container *ContainerDetail) (model.SimpleImageDetail, error) {
	var tmpLibary, tmpFullRepoName string
	repo := strings.Replace(container.Repository, "http://", "", 1)
	repo = strings.Replace(container.Repository, "https://", "", 1)
	idx := strings.Index(repo, "/")
	if idx > 0 {
		tmpLibary = repo[:idx]
		tmpFullRepoName = repo[idx+1:]
	} else {
		tmpLibary = repo
		tmpFullRepoName = ""
	}
	url := fmt.Sprintf("%s/api/v1/scan/reportsBySimpleImageDetails/?full_repo_name=%s&library=%s&tag=%s", s.scannerURL, tmpFullRepoName, tmpLibary, container.RepoTag)
	resp, err := http.Get(url)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("getImageScanDetail http get error. url: %s", url)
		return model.SimpleImageDetail{}, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logging.GetLogger().Error().Msgf("getImageScanDetail http get error. url: %s status code: %d", url, resp.StatusCode)
		return model.SimpleImageDetail{}, errors.New("http code not 200")
	}

	resScanImage := imageInfo{}
	err = json.NewDecoder(resp.Body).Decode(&resScanImage)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get image scan decode error")
		return model.SimpleImageDetail{}, err
	}
	return resScanImage.Data.Item, nil
}

func (s *RiskExplorerService) ResourceDetail(ctx context.Context, clusterKey, namespace, resourceKind, resourceName string) (*ResourceDetail, error) {

	resSvc, _ := assetsSvc.GetResourcesService(ctx)
	containers, _, err := resSvc.GetResourceContainers(ctx, dal.ResourceContainersQuery().WithCluster(clusterKey).WithNamespace(namespace).WithResourceKind(assets.ResourceKind(resourceKind)).WithResourceName(resourceName), 0, 100)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get resource containers in ResourceDetail error: %s %s %s %s", clusterKey, namespace, resourceKind, resourceName)
		return nil, err
	}
	pods, _, err := resSvc.GetResourcePods(ctx,
		dal.ResourcePodssQuery().
			WithCluster(clusterKey).
			WithNamespace(namespace).
			WithResourceKind(assets.ResourceKind(resourceKind)).
			WithResourceName(resourceName),
		-1, -1)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get resource pods in ResourceDetail error: %s %s %s %s", clusterKey, namespace, resourceKind, resourceName)
	}
	rdetail := new(ResourceDetail)
	rdetail.Containers = make([]*ContainerDetail, len(containers))
	for i, container := range containers {
		rdetail.Containers[i] = new(ContainerDetail)
		repo, tag := getRepositoryAndTagFromImage(container.Image)
		rdetail.Containers[i].Repository = repo
		rdetail.Containers[i].RepoTag = tag
		rdetail.Containers[i].Name = container.Name
		rdetail.Containers[i].InstancesRunning = make([]NodeInfo, len(pods))
		for j, pod := range pods {
			rdetail.Containers[i].InstancesRunning[j] = NodeInfo{
				Node:    pod.HostIP,
				PodName: pod.PodName,
			}
		}
		imageDetail, err := s.getImageScanDetail(ctx, rdetail.Containers[i])
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get image scan detail error: %s %s %s %s", clusterKey, namespace, resourceKind, resourceName)
			continue
		}
		imageVulnsData, ok := getImageVulnsRiskData(ctx, imageDetail.Vulnerabilities, imageDetail.Sensitives)
		if ok {
			rdetail.Containers[i].RiskItems = append(rdetail.Containers[i].RiskItems, &RiskTypeDetail{
				RiskType: string(KeyImageVulns.Key),
				RiskData: imageVulnsData,
			})
		}
	}

	return rdetail, nil
}
