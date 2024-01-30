package imagesecStore

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageRedisDao struct {
	redisCli *redis.Client
}

type OnlineImageDal interface {
	GetOnlineImageUUID(ctx context.Context) ([]uint32, error)
}

func (dal *ImageRedisDao) GetOnlineImageUUID(ctx context.Context) ([]uint32, error) {

	if dal.redisCli == nil {
		return nil, fmt.Errorf("not get redis client")
	}
	uuids := make([]uint32, 0)
	start := 0
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()
	for {
		opt := &redis.ZRangeBy{
			Min:   strconv.Itoa(int(start)),
			Max:   consts.RedisPositiveInfinity,
			Count: consts.DefaultMaxLimit,
		}
		scores := dal.redisCli.ZRangeByScoreWithScores(ctx, consts.OnlineImageRedisKey, opt)
		result, err := scores.Result()
		if err != nil {
			return nil, err
		}
		ans := make([]int, 0)
		for i := range result {
			if int(result[i].Score) <= 0 {
				continue
			}
			ans = append(ans, int(result[i].Score))
		}

		if len(ans) == 0 {
			break
		}
		ans = util.DuplicateIntSlice(ans)
		sort.Ints(ans)
		start = ans[len(ans)-1] + 1
		for i := range ans {
			uuids = append(uuids, uint32(ans[i]))
		}
		uuids = util.DuplicateUint32Slice(uuids)
	}
	return uuids, nil
}

func NewImageRedisDao(redisCli *redis.Client) *ImageRedisDao {
	return &ImageRedisDao{
		redisCli: redisCli,
	}
}
