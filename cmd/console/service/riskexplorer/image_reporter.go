package riskexplorer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageVulnsReporter struct {
	redisCli *redis.Client
}

func NewImageVulnsReporter(redisCli *redis.Client) *ImageVulnsReporter {
	return &ImageVulnsReporter{
		redisCli: redisCli,
	}
}
func (i *ImageVulnsReporter) Name() string {
	return "image_reporter"
}

func (i *ImageVulnsReporter) LoadImageRiskLevels(ctx context.Context, images []string) (map[string]map[string]resSumm, error) {
	imageSums := make(map[string]map[string]resSumm, len(images))
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmds := make([]struct {
		cmd      *redis.StringCmd
		image    string
		riskType RiskTypeDesc
	}, len(images))
	_, err := i.redisCli.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for riskTypeKey, riskType := range riskTypes {
			for i, image := range images {
				cmds[i].cmd = pipe.Get(ctx, getRedisKey(riskTypeKey, image))
				cmds[i].image = image
				cmds[i].riskType = riskType
			}
		}

		return nil
	})
	if err != nil && err != redis.Nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "failed to get redis. ")
		return nil, err
	}
	for _, cmd := range cmds {
		res, err := cmd.cmd.Result()
		if err == redis.Nil {
			continue
		} else if err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "failed to get. ")
			continue
		}
		var isum model.ImageVulnsSumData
		err = json.Unmarshal([]byte(res), &isum)
		if err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "failed to get. ")
			continue
		}
		isumRes := getSeverityFrom(isum)
		isumm, ok := imageSums[cmd.image]
		if !ok {
			isumm = make(map[string]resSumm, 3)
			imageSums[cmd.image] = isumm
		}
		isumm[cmd.riskType.Key] = isumRes
	}
	return imageSums, nil
}

func getSeverityFrom(isum model.ImageVulnsSumData) resSumm {
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

func getRedisKey(riskTypeKey, imageID string) string {
	return fmt.Sprintf("riskexp-%s-%s", riskTypeKey, imageID)
}

type resSumm struct {
	severity   Severity
	statsCount int64
}
type ImageVulnsSummary struct {
	summaryData map[string]map[string]resSumm // imageID -> summary
	resToImages util.Multimap                 // resourceKey -> the list of imageIDs
}

func (s ImageVulnsSummary) ResourceSummary(tx context.Context, clusterKey, namespace, resourceKind, resourceName string) (sums map[string]Summary, err error) {
	key := getResKey(clusterKey, namespace, resourceKind, resourceName)
	imageIDs := s.resToImages.Get(key)
	if len(imageIDs) == 0 {
		return make(map[string]Summary, 0), nil
	}

	sums = make(map[string]Summary, 3)
	for riskTypeKey, riskType := range riskTypes {
		maxRiskTypeSeverity := SeverityUnknown
		var count int
		for _, iobj := range imageIDs {
			imageID := iobj.(string)
			allSumm, ok := s.summaryData[imageID]
			if ok {
				summ, sok := allSumm[riskTypeKey]
				if sok {
					if summ.severity > maxRiskTypeSeverity {
						maxRiskTypeSeverity = summ.severity
					}
					count += int(summ.statsCount)
				}

			}
		}
		sums[riskTypeKey] = Summary{
			Count:    count,
			Severity: maxRiskTypeSeverity,
			RiskType: riskType,
		}
	}

	return sums, nil
}

func (i ImageVulnsSummary) Name() string {
	return "image_reporter"
}
