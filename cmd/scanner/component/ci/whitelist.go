package ci

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
)

type WhitelistManager struct {
	dal store.ScanCiInterface
}

func NewWhiteList(dal store.ScanCiInterface) WhitelistManager {
	return WhitelistManager{dal: dal}
}

func (w *WhitelistManager) DeleteWhitelist(ctx context.Context, id int64) error {
	return w.dal.DeleteWhitelist(ctx, id)
}

func (w *WhitelistManager) UpdateWhitelist(ctx context.Context, whitelist []scanner_ci.CiWhitelistReq) error {
	white := []scanner_ci.CiWhitelist{}
	for _, v := range whitelist {
		white = append(white, scanner_ci.CiWhitelist{ID: v.ID, Name: v.Name, ExpireTime: v.ExpireTime})
	}
	return w.dal.UpdateWhitelist(ctx, white)
}

func (w *WhitelistManager) CreateWhitelist(ctx context.Context, whitelist []scanner_ci.CiWhitelistReq) error {
	whitelists := []scanner_ci.CiWhitelist{}
	for _, v := range whitelist {
		whitelists = append(whitelists, scanner_ci.CiWhitelist{Name: v.Name, ExpireTime: v.ExpireTime})
	}

	nowWhite, cnt, err := w.GetWhiteList(ctx, scanner_ci.WhitelistParams{})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get whitelist error when create whitelist")
		return err
	}

	if cnt >= 1000 {
		return fmt.Errorf("白名单上限1000 添加失败 请先删除")
	}

	mp := make(map[string]struct{}, 0)
	mpAdd := make(map[string]struct{}, 0)
	for _, v := range nowWhite {
		mp[v.Name+strconv.FormatInt(v.ExpireTime, 10)] = struct{}{}
	}

	addWhitelist := []scanner_ci.CiWhitelist{}
	for _, v := range whitelists {
		if _, ok := mp[v.Name+strconv.FormatInt(v.ExpireTime, 10)]; !ok {
			if _, ok := mpAdd[v.Name+strconv.FormatInt(v.ExpireTime, 10)]; !ok {
				mpAdd[v.Name+strconv.FormatInt(v.ExpireTime, 10)] = struct{}{}
				addWhitelist = append(addWhitelist, v)
			}
		}
	}

	return w.dal.CreateWhitelist(ctx, addWhitelist)
}

func (w *WhitelistManager) GetWhiteList(ctx context.Context, params scanner_ci.WhitelistParams) ([]scanner_ci.CiWhitelist, int64, error) {
	return w.dal.GetWhitelist(ctx, params)
}

func (w *WhitelistManager) MatchWhiteList(ctx context.Context, name string) (bool, error) {
	whitelist, _, err := w.GetWhiteList(ctx, scanner_ci.WhitelistParams{Limit: 10000, Offset: 0, NowTime: time.Now().UnixMilli()})
	if err != nil {
		logging.GetLogger().Err(err).Msg("get whitelist error")
		return false, err
	}
	regs := []*regexp.Regexp{}
	for _, v := range whitelist {
		reg, err := regexp.Compile(v.Name)
		if err != nil {
			logging.GetLogger().Warn().Msgf("compile failed %s", v.Name)
			continue
		}
		regs = append(regs, reg)
	}
	for k := range regs {
		if regs[k].Match([]byte(name)) {
			return true, nil
		}
	}
	return false, nil
}
