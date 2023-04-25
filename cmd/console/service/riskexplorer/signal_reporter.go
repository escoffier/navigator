package riskexplorer

import (
	"context"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SignalReporter struct {
	sherlockCli *echelper.SherlockClient
}

func NewSignalReporter(sherlockClient *echelper.SherlockClient) *SignalReporter {
	return &SignalReporter{
		sherlockCli: sherlockClient,
	}
}
func (r *SignalReporter) Name() string {
	return "signal_reporter"
}

func (r *SignalReporter) LoadSummary(ctx context.Context, assetsSummary []*NamespaceSummary) (TotalSummary, error) {
	riskStatsMap := map[string]map[string][]echelper.RiskStatsItem{}
	clusterSet := map[string]struct{}{}
	for _, v := range assetsSummary {
		if _, ok := clusterSet[v.ClusterKey]; ok {
			continue
		} else {
			clusterSet[v.ClusterKey] = struct{}{}
		}

		res, err := r.sherlockCli.RiskStats(ctx, v.ClusterKey)
		if err != nil {
			return nil, err
		}

		// 过滤掉部分事件类型：镜像安全、CIS扫描
		for k, riskStatsItems := range res {
			filteredRiskStatsItems := make([]echelper.RiskStatsItem, 0)
			for i := range riskStatsItems {
				if util.ContainsString([]string{"imageSecurity", "CIS/Nginx", "CIS/Postgres", "CIS/Redis", "CIS/SSH"}, riskStatsItems[i].EnKey) {
					continue
				}
				filteredRiskStatsItems = append(filteredRiskStatsItems, riskStatsItems[i])
			}
			res[k] = filteredRiskStatsItems
		}

		riskStatsMap[v.ClusterKey] = res
	}

	return EventSummary{
		riskStatsMap: riskStatsMap,
	}, nil
}

type EventSummary struct {
	riskStatsMap map[string]map[string][]echelper.RiskStatsItem
}

func (s EventSummary) ResourceSummary(ctx context.Context, clusterKey, namespace, resourceKind, resourceName string) (map[string]Summary, error) {
	cMap, ok := s.riskStatsMap[clusterKey]
	if !ok {
		return map[string]Summary{}, nil
	}

	key := fmt.Sprintf("%s%s(%s)", namespace, resourceName, resourceKind)

	sums := map[string]Summary{}
	for _, risk := range cMap[key] {
		sums[risk.EnKey] = Summary{
			Count:    risk.Count,
			Severity: getSeverityFromSignalSeverity(risk.Severity),
			RiskType: RiskTypeDesc{
				Key:       risk.EnKey,
				DisplayZh: risk.ZhKey,
				DisplayEn: risk.EnKey,
			},
		}
	}

	return sums, nil
}

func getSeverityFromSignalSeverity(severity int) Severity {
	if severity <= 3 {
		return SeverityHigh
	} else if severity <= 5 {
		return SeverityMedium
	} else if severity <= 7 {
		return SeverityLow
	} else {
		return SeverityUnknown
	}
}

func (s EventSummary) Name() string {
	return "event_reporter"
}
