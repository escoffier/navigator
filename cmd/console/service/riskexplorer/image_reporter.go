package riskexplorer

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
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
func (ir *ImageVulnsReporter) Name() string {
	return "image_reporter"
}

type cmdInfo struct {
	cmd      *redis.StringCmd
	image    string
	riskType RiskTypeDesc
}

func (ir *ImageVulnsReporter) LoadImageRiskLevels(ctx context.Context, images []string) (map[string]map[string]ResSumm, error) {
	imageSums := make(map[string]map[string]ResSumm, len(images))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmds := make([]cmdInfo, 0, len(riskTypes)*len(images))
	pipe := ir.redisCli.Pipeline()
	for riskTypeKey, riskType := range riskTypes {
		for _, image := range images {
			rkey := getRedisKey(riskTypeKey, image)
			cmds = append(cmds, cmdInfo{
				cmd:      pipe.Get(ctx, rkey),
				image:    image,
				riskType: riskType,
			})
		}
	}

	_, err := pipe.Exec(ctx)
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
			isumm = make(map[string]ResSumm, 3)
			imageSums[cmd.image] = isumm
		}
		isumm[cmd.riskType.Key] = isumRes
	}
	return imageSums, nil
}

func getSeverityFrom(isum model.ImageVulnsSumData) ResSumm {
	res := ResSumm{}
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

func (ir *ImageVulnsReporter) LoadSummary(ctx context.Context, assetsSummary []*NamespaceSummary) (TotalSummary, error) {
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

	imageSumm, lerr := ir.LoadImageRiskLevels(ctx, images)
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

type ResSumm struct {
	severity   Severity
	statsCount int64
}
type ImageVulnsSummary struct {
	summaryData map[string]map[string]ResSumm // imageID -> summary
	resToImages util.Multimap                 // resourceKey -> the list of imageIDs
}

func (s ImageVulnsSummary) ResourceSummary(tx context.Context, clusterKey, namespace, resourceKind, resourceName string) (sums map[string]Summary, err error) {
	key := getResKey(clusterKey, namespace, resourceKind, resourceName)
	imageIDs := s.resToImages.Get(key)
	if len(imageIDs) == 0 {
		return make(map[string]Summary, 0), nil // nolint
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

func (s ImageVulnsSummary) Name() string {
	return "image_reporter"
}
