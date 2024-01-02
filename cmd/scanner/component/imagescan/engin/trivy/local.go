package scanTrivy

import (
	"context"
	"errors"
	"fmt"
	"os"

	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/analyzer"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/analyzer/config"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/applier"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/artifact"
	local2 "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/artifact/local"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/cache"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type Local struct {
	Log *scannerUtils.LogEvent
}

func (s *TrivySrv) inspect(ctx context.Context, art artifact.Artifact, c cache.LocalArtifactCache) (ftypes.ArtifactDetail, error) {
	imageInfo, err := art.Inspect(ctx)
	if err != nil {
		return ftypes.ArtifactDetail{}, err
	}
	s.Log.Debug().Interface("imageInfo", imageInfo).Msg("local inspect")

	a := applier.NewApplier(c)
	mergedLayer, err := a.ApplyLayers(imageInfo.ID, imageInfo.BlobIDs)
	if err != nil {
		switch {
		case errors.Is(err, analyzer.ErrUnknownOS), errors.Is(err, analyzer.ErrNoPkgsDetected):
			s.Log.Debug().Msgf("not found os info:%v", err)
		default:
			s.Log.Err(err).Msg("failed to inspect layer")
			return ftypes.ArtifactDetail{}, err
		}
	}
	return mergedLayer, nil
}

func (s *TrivySrv) AnalyzePackages(ctx context.Context, prepare *imagesec.PrepareScan) (report.Report, error) {
	graphDataPath := make([]string, 0)
	for i := range prepare.Layers {
		if prepare.Layers[i].LayerFilePath == "" {
			continue
		}
		graphDataPath = append(graphDataPath, prepare.Layers[i].LayerFilePath)
	}
	s.Log.Info().Strs("graphDataPath", graphDataPath).Msg("local scan AnalyzePackages")

	rep := report.Report{Results: make(report.Results, 0)}
	var res ftypes.ArtifactDetail

	ca := cache.NewRedisCacheWithRedisCacheClient(s.RedisCli)
	for _, v := range graphDataPath {
		if !dirExists(v) {
			s.Log.Debug().Str("layer", v).Msg("bypass not exits path")
			continue
		}

		s.Log.Debug().Str("layer", v).Msg("start analyze image layer local path")

		art, err := local2.NewArtifact(v, ca, artifact.Option{
			Offline: true,
			// DisabledAnalyzers: global.DisableTypes,
			// Slow:              global.CiOpt.Slow,
		},
			config.ScannerOption{})
		if err != nil {
			s.Log.Err(err).Msg("NewArtifact")
			return rep, fmt.Errorf("create artifact err:%v", err)
		}

		detail, err := s.inspect(context.Background(), art, ca)
		if err != nil {
			if errors.Is(err, analyzer.ErrNoPkgsDetected) || errors.Is(err, analyzer.ErrUnknownOS) {
				// try next layer
				s.Log.Debug().Str("layer", v).Msgf("not support os or not found pkg,try next layer.%v", err)
				continue
			}
			s.Log.Err(err).Str("layer", v).Msg("inspect image")
			return rep, err
		}
		if len(detail.Packages) == 0 {
			s.Log.Debug().Str("layer", v).Msg("not found packages")
		}
		if len(detail.Applications) == 0 {
			s.Log.Debug().Str("layer", v).Msg("not found applications")
		}

		s.Log.Debug().
			Str("layer", v).
			Int("pkgCount", len(detail.Packages)).
			Int("appCount", len(detail.Applications)).
			Msg("analyze layer end")

		if len(res.Packages) == 0 {
			// we inspect from top to bottom,so not need to add packages once found packages in upper layer
			// todo: should break ?
			res.Packages = append(res.Packages, detail.Packages...)
		}
		res.Applications = append(res.Applications, detail.Applications...)
		res.Misconfigurations = append(res.Misconfigurations, detail.Misconfigurations...)
		if detail.OS != nil {
			res.OS = detail.OS
		}
	}
	rep.Results = append(rep.Results, report.Result{Artifact: res})

	return rep, nil
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func NewLocalAnalyzer() *Local {
	l := &Local{}
	return l
}
