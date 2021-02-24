package riskexplorer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/mgo.v2/bson"
)

var (
	singleton *RiskExplorerService
	initOnce  sync.Once
)

func InitAndGetRiskExplorerService(mongoDB *mongo.Database, onlineVulnsSvc *assetsSvc.OnlineVulnsService) *RiskExplorerService {
	initOnce.Do(func() {
		singleton = &RiskExplorerService{
			mongoDB:        mongoDB,
			onlineVulnsSvc: onlineVulnsSvc,
			reporters:      make([]RiskTypeReporter, 0, 2),
		}
		// add more reporters here
	})
	return singleton
}

func GetRiskExplorerService() (*RiskExplorerService, bool) {
	return singleton, singleton != nil
}

type RiskType string

const (
	KeyCompliance       RiskType = "ComplianceCheck"
	KeyImageVulns       RiskType = "ImageVulnerabilities"
	KeyAppAttacks       RiskType = "ApplicationAttacks"
	KeyRuntimeDetection RiskType = "RuntimeDetection"
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

type RiskTypeReporter interface {
	Key() RiskType
	LoadSummary(tx context.Context) (TotalSummary, error)
	LoadDetails(tx context.Context, cluster, namespace, service string) (ServiceDetails, error)
}

type TotalSummary interface {
	ServiceSummary(tx context.Context, cluster, namespace, service string) (severity Severity, statsCount int, err error)
	Key() RiskType
}

type ServiceDetails interface {
	ServiceDetails(ctx context.Context) (json.RawMessage, error)
	ContainerDetails(ctx context.Context, name string, digest string) (json.RawMessage, error)
	Key() RiskType
}

type RiskExplorerService struct {
	mongoDB        *mongo.Database
	onlineVulnsSvc *assetsSvc.OnlineVulnsService
	reporters      []RiskTypeReporter
}

func (s *RiskExplorerService) WholeSummary(ctx context.Context, cluster string) ([]*NamespaceSummary, error) {
	// TODO: decouple the vulns with assets and make the imageVulns as a reporter
	items, err := s.onlineVulnsSvc.ListCurrentOnlineVulnerabilities(ctx, cluster, 0, 10000)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("list current vulns error for cluster %s", cluster)
		return nil, err
	}

	summaries := make([]TotalSummary, 0, len(s.reporters))
	for _, reporter := range s.reporters {
		summary, reErr := reporter.LoadSummary(ctx)
		if reErr != nil {
			logging.GetLogger().Err(reErr).Msgf("reporter %s error: %v", reporter.Key(), reErr)
			continue
		}
		summaries = append(summaries, summary)
	}
	nsMap := make(map[string]*NamespaceSummary, 10)
	for _, item := range items {
		nsItem, nsExist := nsMap[item.Namespace]
		if !nsExist {
			nsItem = new(NamespaceSummary)
			nsItem.Name = item.Namespace
			nsMap[item.Namespace] = nsItem
		}

		var svcItem *ServiceSummary
		for _, svc := range nsItem.ServicesList {
			if item.ServiceName == svc.ServiceName {
				svcItem = svc
				break
			}
		}
		if svcItem == nil {
			svcItem = new(ServiceSummary)
			svcItem.ServiceName = item.ServiceName
			svcItem.Namespace = item.Namespace
			svcItem.ContainersList = make([]*ContainerSummary, 0, 2)
			svcItem.RiskTypes = make(map[RiskType]int, 1)
			nsItem.ServicesList = append(nsItem.ServicesList, svcItem)
		}
		for _, rcont := range item.RunningContainers {
			var contSumm *ContainerSummary
			for _, container := range svcItem.ContainersList {
				if container.ContainerID == rcont {
					contSumm = container
					break
				}
			}
			if contSumm == nil {
				contSumm = new(ContainerSummary)
				contSumm.ContainerID = rcont
				sps := strings.Split(rcont, "@")
				if len(sps) > 0 {
					contSumm.Name = sps[0]
				}
				contSumm.ServiceName = item.ServiceName
				contSumm.Namespace = item.Namespace
				contSumm.RiskTypes = make(map[RiskType]int, 0)
				svcItem.ContainersList = append(svcItem.ContainersList, contSumm)
			}
		}

		svcItem.RiskLevel = int(SeverityUnknown)
		svcItem.FinalSeverity = SeverityUnknown.String()
		imageVulnsCount := 0
		// make up the image scans vulnerabilities
		for _, vulns := range item.TopVulns {
			severity := GetSeverityFromString(vulns.Severity)

			if int(severity) > svcItem.RiskLevel {
				svcItem.RiskLevel = int(severity)
				svcItem.FinalSeverity = severity.String()
			}
			if severity > SeverityNegligible {
				imageVulnsCount++
			}
		}
		if imageVulnsCount > 0 {
			svcItem.RiskTypes[KeyImageVulns] = imageVulnsCount
		}

		for _, summ := range summaries {
			sev, statsCnt, err := summ.ServiceSummary(ctx, cluster, item.Namespace, svcItem.ServiceName)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("%s-%s-%s reporter %s summary err", cluster, item.Namespace, svcItem.ServiceName, summ.Key())
				continue
			}
			if sev > SeverityNegligible {
				svcItem.RiskTypes[summ.Key()] = statsCnt
			}
		}
	}

	nsSlice := make([]*NamespaceSummary, len(nsMap))
	i := 0
	for _, nsSumm := range nsMap {
		nsSlice[i] = nsSumm
		i++
	}
	return nsSlice, nil
}

func getImageVulnsRiskData(ctx context.Context, assetCont *model.AssetContainer) (json.RawMessage, bool) {
	idStr := ""
	if !assetCont.TaskID.IsZero() {
		idStr = assetCont.TaskID.Hex()
	}
	imageVulns := ImageVulnsDetails{
		ScanTaskID:      idStr,
		SensitiveFiles:  assetCont.SensitiveFiles,
		Vulnerabilities: assetCont.Vulnerabilities,
		HarborURL:       assetCont.HarborURL,
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
		logging.GetLogger().Err(err).Msgf("get image vulns data error. assetCont: %+v", assetCont)
		return nil, false
	}
	return mar, true
}

func (s *RiskExplorerService) ServiceDetail(ctx context.Context, cluster, namespace, service string) (*ServiceDetail, error) {
	detailHandlers := make([]ServiceDetails, 0, len(s.reporters))
	for _, reporter := range s.reporters {
		sdetails, derr := reporter.LoadDetails(ctx, cluster, namespace, service)
		if derr != nil {
			logging.GetLogger().Err(derr).Msgf("%s reporter load details error", reporter.Key())
			continue
		}
		detailHandlers = append(detailHandlers, sdetails)
	}

	podsNames, err := assets.GetPodNamesFromService(s.mongoDB, cluster, namespace, service)
	filter := bson.M{
		"isDeleted": false,
		"cluster":   cluster,
		"namespace": namespace,
		"podName":   bson.M{"$in": podsNames},
	}
	findOptions := options.Find().SetMaxTime(time.Second * 10)
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := s.mongoDB.Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(ctx); err != nil {
			logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
		}
	}()

	svcDetail := new(ServiceDetail)

	for _, dhandle := range detailHandlers {
		msg, err := dhandle.ServiceDetails(ctx)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("service detail err.")
			continue
		}
		if len(msg) > 0 {
			svcDetail.RiskItems = append(svcDetail.RiskItems, &RiskTypeDetail{
				RiskType: string(dhandle.Key()),
				RiskData: msg,
			})
		}
	}

	contMap := make(map[string]*ContainerDetail, 2)
	foundAny := false
	for cursor.Next(ctx) {
		foundAny = true

		var container model.AssetContainer
		err := cursor.Decode(&container)
		if err != nil {
			return nil, apperror.NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't decode document: %w", err))
		}

		nameDigest := fmt.Sprintf("%s@%s", container.Name, container.Digest)

		var contDetail *ContainerDetail
		var ok bool
		if contDetail, ok = contMap[nameDigest]; !ok {
			contDetail = &ContainerDetail{
				Name:                container.Name,
				Digest:              container.Digest,
				Repository:          container.Repository,
				RepoTag:             container.Tag,
				InstancesRunning:    make([]NodeInfo, 0, 10),
				InstancesTerminated: make([]NodeInfo, 0),
				InstancesWaiting:    make([]NodeInfo, 0, 0),
				RiskItems:           make([]*RiskTypeDetail, 0, len(s.reporters)),
			}
			imageVulnsData, ok := getImageVulnsRiskData(ctx, &container)
			if ok {
				contDetail.RiskItems = append(contDetail.RiskItems, &RiskTypeDetail{
					RiskType: string(KeyImageVulns),
					RiskData: imageVulnsData,
				})
			}

			contMap[nameDigest] = contDetail
		}

		node := NodeInfo{
			PodName: container.PodName,
			Node:    container.Node,
		}

		if container.State == "Terminated" {
			contDetail.InstancesTerminated = append(contDetail.InstancesTerminated, node)
		} else if container.State == "Running" {
			contDetail.InstancesRunning = append(contDetail.InstancesRunning, node)
		} else {
			contDetail.InstancesWaiting = append(contDetail.InstancesWaiting, node)
		}
	}

	err = cursor.Err()
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Cursor error: %w", err))
	}

	if !foundAny {
		return nil, apperror.NewMongoError(http.StatusNotFound,
			fmt.Errorf("Such resource has no containers"))
	}

	svcDetail.Containers = make([]*ContainerDetail, len(contMap))
	i := 0
	for _, contDetail := range contMap {
		svcDetail.Containers[i] = contDetail
		i++

		for _, dhandler := range detailHandlers {
			raw, err := dhandler.ContainerDetails(ctx, contDetail.Name, contDetail.Digest)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("get cont detail for %s/%s errored for reporter %s", contDetail.Name, contDetail.Digest, dhandler.Key())
				continue
			}
			if len(raw) > 0 {
				contDetail.RiskItems = append(contDetail.RiskItems, &RiskTypeDetail{
					RiskType: string(dhandler.Key()),
					RiskData: raw,
				})
			}
		}
	}

	return svcDetail, nil
}
