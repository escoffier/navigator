package riskexplorer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// TODO
type ImageVulnsReporter struct {
	redisCli *redis.Client
}

func NewImageVulnsReporter(redisCli *redis.Client) *ImageVulnsReporter {
	return &ImageVulnsReporter{
		redisCli: redisCli,
	}
}
func (i *ImageVulnsReporter) Key() RiskType {
	return KeyImageVulns
}

type ImageVulnsSumData struct {
	CriticalNum int64 `json:"criticalNum"`
	HighNum     int64 `json:"highNum"`
	MediumNum   int64 `json:"mediumNum"`
	LowNum      int64 `json:"lowNum"`
	UnknownNum  int64 `json:"unknownNum"`
}

func (i *ImageVulnsReporter) LoadImageRiskLevels(ctx context.Context, images []string) (map[string]resSumm, error) {
	imageSums := make(map[string]resSumm, len(images))
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmds := make([]struct {
		cmd   *redis.StringCmd
		image string
	}, len(images))
	_, err := i.redisCli.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for i, image := range images {
			cmds[i].cmd = pipe.Get(ctx, getRedisKey(image))
			cmds[i].image = image
		}
		return nil
	})
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "failed to get redis. ")
		return nil, err
	}
	for _, cmd := range cmds {
		res, err := cmd.cmd.Result()
		if err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "failed to get. ")
			continue
		}
		var isum ImageVulnsSumData
		err = json.Unmarshal([]byte(res), &isum)
		if err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "failed to get. ")
			continue
		}
		resSumm := getSeverityFrom(isum)
		imageSums[cmd.image] = resSumm
	}
	return imageSums, nil
}

func getSeverityFrom(isum ImageVulnsSumData) resSumm {
	res := resSumm{}
	if isum.CriticalNum > 0 {
		res.severity = SeverityCritical
	} else if isum.HighNum > 0 {
		res.severity = SeverityHigh
	} else if isum.MediumNum > 0 {
		res.severity = SeverityMedium
	} else if isum.LowNum > 0 {
		res.severity = SeverityLow
	} else {
		res.severity = SeverityUnknown
	}
	res.statsCount = isum.CriticalNum + isum.HighNum
	return res
}
func (i *ImageVulnsReporter) LoadSummary(ctx context.Context, assetsSummary []*NamespaceSummary) (TotalSummary, error) {
	resImageMap := make(util.Multimap, 50)
	imagesSet := make(map[string]struct{}, 50)
	for _, nsSumm := range assetsSummary {
		for _, resSumm := range nsSumm.ResourcesList {
			for _, contSumm := range resSumm.ContainersList {
				imagesSet[contSumm.Image] = struct{}{}
				resImageMap.Put(getResKey(nsSumm.ClusterKey, nsSumm.Name, resSumm.ResourceKind, resSumm.ResourceName), contSumm.Image)
			}
		}
	}
	images := make([]string, 0, len(imagesSet))
	for imageID := range imagesSet {
		images = append(images, imageID)
	}

	imageSumm, lerr := i.LoadImageRiskLevels(ctx, images)
	if lerr != nil {
		logging.GetLogger().WithContext(ctx).Errorf(lerr, "load image risk levels error")
		return nil, lerr
	}
	return ImageVulnsSummary{
		summaryData: imageSumm,
		resToImages: resImageMap,
	}, nil
}
func getResKey(clusterKey, namespace, resourceKind, resourceName string) string {
	return fmt.Sprintf("%s/%s/%s/%s", clusterKey, namespace, resourceKind, resourceName)
}

func getRedisKey(imageID string) string {
	return fmt.Sprintf("riskexp-image-vulns-%s", imageID)
}

type resSumm struct {
	severity   Severity
	statsCount int64
}
type ImageVulnsSummary struct {
	summaryData map[string]resSumm // imageID -> summary
	resToImages util.Multimap      // resourceKey -> the list of imageIDs
}

func (s ImageVulnsSummary) ResourceSummary(tx context.Context, clusterKey, namespace, resourceKind, resourceName string) (severity Severity, statsCount int, err error) {
	key := getResKey(clusterKey, namespace, resourceKind, resourceName)
	imageIDs := s.resToImages.Get(key)
	if len(imageIDs) == 0 {
		return SeverityUnknown, 0, nil
	}
	maxSeverity := SeverityUnknown
	var count int64
	for _, iobj := range imageIDs {
		imageID := iobj.(string)
		summ, ok := s.summaryData[imageID]
		if ok {
			if summ.severity > maxSeverity {
				maxSeverity = summ.severity
				count += summ.statsCount
			}
		}
	}
	return maxSeverity, int(count), nil
}
func (s ImageVulnsSummary) Key() RiskType {
	return KeyImageVulns
}
