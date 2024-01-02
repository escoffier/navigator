package assets

import (
	"regexp"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
)

func (s *SendAssetManager) FilterRepoTag(im container.ImageSummary) container.ImageSummary {
	rt := make([]string, 0)

	for i := range im.RepoTags {
		if s.shouldExclude(im.RepoTags[i]) {
			continue
		}
		rt = append(rt, im.RepoTags[i])
	}
	im.RepoTags = rt
	return im
}

func (s *SendAssetManager) FilterRepoDigest(im container.ImageSummary) container.ImageSummary {
	rt := make([]string, 0)

	for i := range im.RepoDigests {
		if s.shouldExclude(im.RepoDigests[i]) {
			continue
		}
		rt = append(rt, im.RepoDigests[i])
	}
	im.RepoDigests = rt
	return im
}

func (s *SendAssetManager) shouldExclude(im string) bool {
	for _, v := range s.initConfig.ReportConfig.ExcludeImage {
		reg, err := regexp.Compile(v)
		if err != nil {
			s.Log.Err(err).Msg("invalid report exclude image rule,please check config file")
			continue
		}
		match := reg.FindString(im)
		if len(match) > 0 {
			return true
		}
	}
	return false
}

func (s *SendAssetManager) filterImage(images []container.ImageSummary) []container.ImageSummary {
	ans := make([]container.ImageSummary, 0)
	for i := range images {
		im := images[i]
		if im.ID == "" {
			continue
		}

		im = s.FilterRepoTag(im)
		im = s.FilterRepoDigest(im)
		if len(im.RepoTags) == 0 || len(im.RepoDigests) == 0 {
			continue
		}
		ans = append(ans, im)
	}
	return ans
}

func (s *SendAssetManager) getMqTimeout() int64 {
	s.Lock()
	defer s.Unlock()
	return s.initConfig.ReportConfig.MqTimeout
}

func (s *SendAssetManager) getReportInterval() int64 {
	s.Lock()
	defer s.Unlock()
	if s.nodeImageConfig.SyncInterval <= 0 {
		return defaultReportInterval
	}
	return s.nodeImageConfig.SyncInterval * 60
}
