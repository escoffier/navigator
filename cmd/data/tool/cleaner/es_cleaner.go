package cleaner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ElasticsearchCleaner struct {
	indexPrefixes []string
	esCli         *elastic.Client
}

func NewESCleaner(esURL string, indexPrefixes []string) (*ElasticsearchCleaner, error) {
	esCli, err := elastic.NewClient(elastic.SetURL(esURL))
	if err != nil {
		return nil, err
	}

	return &ElasticsearchCleaner{esCli: esCli, indexPrefixes: indexPrefixes}, nil
}

const (
	esInterval = time.Second
)

func (e *ElasticsearchCleaner) Clean(ctx context.Context, daysOffset int) error {
	indexes, err := e.getAllIndexes(ctx)
	if err != nil {
		return err
	}

	dateFilter := generateDateFilter(daysOffset)

	for _, index := range indexes {
		logging.GetLogger().Info().Msgf("index:%s", index.Index)
		if e.checkNeedDeleteIndex(index.Index, dateFilter) {
			err = e.deleteIndex(ctx, index.Index)
			if err != nil {
				return err
			}

			logging.GetLogger().Info().Msgf("delete index:%s successfully", index.Index)
			time.Sleep(esInterval)
		}
	}

	return nil
}

func (e *ElasticsearchCleaner) checkNeedDeleteIndex(index string, dateFilter time.Time) bool {
	for _, indexPrefix := range e.indexPrefixes {
		if !strings.HasPrefix(index, indexPrefix) {
			continue
		}

		logging.GetLogger().Info().Msgf("index:%s, match:%s", index, indexPrefix)
		date := strings.TrimPrefix(index, indexPrefix)

		t, err := time.ParseInLocation("2006-01-02", date, time.Local)
		if err != nil {
			logging.GetLogger().Warn().Msgf("unexpected indexName:%s", index)
			continue
		}

		if t.Before(dateFilter) {
			return true
		}
	}

	return false
}

func (e *ElasticsearchCleaner) getAllIndexes(ctx context.Context) (rsp elastic.CatIndicesResponse, err error) {
	getFunc := func() error {
		var _err error
		rsp, _err = e.esCli.CatIndices().Do(ctx)
		if _err != nil {
			logging.GetLogger().Error().Msgf("getAllIndexes fail, err:%s", _err.Error())
			return fmt.Errorf("getAllIndexes fail, err:%w", _err)
		}

		return nil
	}

	err = util.WithRetry(getFunc, util.DefaultRetryConf)
	return rsp, err
}

func (e *ElasticsearchCleaner) deleteIndex(ctx context.Context, index string) error {
	deleteFunc := func() error {
		rsp, err := e.esCli.DeleteIndex(index).Do(ctx)
		if err != nil {
			logging.GetLogger().Info().Msgf("delete index:%s fail, err:%s", index, err.Error())
			return fmt.Errorf("delete index:%s, fail, err:%w", index, err)
		}

		logging.GetLogger().Info().Msgf("deleteIndex:%s, acknowledged:%t", index, rsp.Acknowledged)
		if !rsp.Acknowledged {
			return fmt.Errorf("delete index:%s not acknowledged", index)
		}

		return nil
	}

	return util.WithRetry(deleteFunc, util.DefaultRetryConf)
}

func generateDateFilter(daysOffset int) time.Time {
	timeFilter := time.Now().Add(-time.Hour * 24 * time.Duration(daysOffset))
	return time.Date(timeFilter.Year(), timeFilter.Month(), timeFilter.Day(),
		0, 0, 0, 0, timeFilter.Location())
}
