package scanjob

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	aviraengin "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/avira"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/hm"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

func (s *RegImageScan) PrepareScan(ctx context.Context, ta imagesecTypes.ScanSubTask) (*types.PrepareScan, error) {

	res := &types.PrepareScan{
		Subtask:      ta,
		Layers:       make([]types.ImageLayer, 0),
		ImageRootDir: s.ScanP.GenRootDir(ctx, ta),
		Image: imagesecModel.Image{
			UniqueID:  ta.RegImageMeta.UniqueID,
			Host:      ta.RegImageMeta.Host,
			Repo:      ta.RegImageMeta.Repo,
			Tag:       ta.RegImageMeta.Tag,
			Digest:    ta.RegImageMeta.Digest,
			ImageUUID: ta.RegImageMeta.ImageUUID,
		},
		UserDockerCli: false,
		LayerFile:     make(map[string][]string),
		Errs:          make([]error, 0),
	}
	layers, err := s.ScanP.PullImage(ctx, ta, res)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("image", ta.RegImageMeta).Msg("PrepareScan")
		return res, err
	}
	res.Layers = layers

	if err := s.ScanP.PrepareFile(ctx, ta, res); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("image", ta.RegImageMeta).Msg("PrepareScan")
		return res, err
	}

	for i := range res.Errs {
		logging.Get().Err(res.Errs[i]).Str("module", "imagescan").Interface("image", ta.RegImageMeta).Msg("PrepareScan")
	}
	if len(res.Errs) > 0 {
		return nil, fmt.Errorf("not prepare for image scan")
	}

	// logging.Get().Debug().Str("module", "imagescan").Interface("scanP", res).Interface("image", ta.RegImageMeta).
	// 	Msg("PrepareScan")

	return res, nil
}

func (s *RegImageScan) ScanVuln(ctx context.Context, prepare *types.PrepareScan) (imagesecTypes.ScanResult, error) {
	res := imagesecTypes.ScanResult{}
	ta := prepare.Subtask
	im, err := s.changCacheUrl(ta.RegImageMeta.ImageName())
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("imageName", ta.RegImageMeta.ImageName()).Msg("changCacheUrl")
		return res, err
	}

	rep, err := s.TrivyEngin.ScanVuln(ctx, im)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("imageName", im).Msg("ScanVuln")
		return res, err
	}

	if rep != nil && rep.Metadata.OS != nil {
		res.OS = ftypes.OS{
			Family: rep.Metadata.OS.Family,
			Name:   rep.Metadata.OS.Name,
			Eosl:   rep.Metadata.OS.Eosl,
		}
	}

	for _, r := range rep.Results {
		// base info
		vulnRes := imagesecTypes.VulnResult{Scanned: true}
		vulnRes.Type = r.Type
		vulnRes.Class = string(r.Class)
		vulnRes.Target = r.Target

		res.OriginArtifact = r.Artifact

		logging.Get().Debug().Str("module", "imagescan").Int("packageNum", len(r.Packages)).Msg("transform res")
		for _, v := range r.Packages {
			pkg := imagesecTypes.Package{
				Name:       v.Name,
				Version:    v.Version,
				SrcName:    v.SrcName,
				SrcVersion: v.SrcVersion,
				License:    v.License,
				FilePath:   v.FilePath,
				Layer:      v.Layer.Digest,
			}
			vulnRes.Packages = append(vulnRes.Packages, pkg)
		}

		// extract vulns
		for _, v := range r.Vulnerabilities {
			vulnBrief := imagesecTypes.VulnerabilityBrief{
				Severity:         v.Severity,
				Class:            string(r.Class),
				ID:               v.VulnerabilityID,
				PkgName:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Layer:            v.Layer.Digest,
			}
			vulnRes.Vulnerabilities.Vulnerabilities = append(vulnRes.Vulnerabilities.Vulnerabilities, vulnBrief)
		}
		res.VulnResults = append(res.VulnResults, vulnRes)
	}

	logging.Get().Info().Str("module", "imagescan").Interface("vuln", res.VulnResults).Msg("ScanVuln")
	return res, nil
}

func (s *RegImageScan) AviraSrv(ctx context.Context, prepare *types.PrepareScan) (imagesecTypes.MalwareResults, error) {
	mas := imagesecTypes.MalwareResults{
		Scanned:          false,
		AviraScanResults: make([]imagesecTypes.AviraScanResult, 0),
		// 后期支持
		AviraDBVersion:     imagesecTypes.AviraDBVersion{},
		AviraEngineVersion: imagesecTypes.AviraEngineVersion{},
	}
	if os.Getenv("AviraSrv") == consts.FalseString {
		return mas, nil
	}
	if prepare == nil || !prepare.Subtask.DeepScan {
		return mas, nil
	}

	logging.Get().Info().Str("module", "imagescan").Str("scanTask", prepare.Subtask.LogStr()).Msg("AviraSrv start")

	// 为啥要在这里获取呢？因为如果不开启深度扫描，是不用实例化引擎的
	// FIXME 关闭深度扫描时要关闭引擎
	aviraE, err := aviraengin.NewSavServer()
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ScanAvira NewSavServer")
		return mas, err
	}
	res := make([]imagesecTypes.AviraScanResult, 0)

	client, err := aviraE.GetClient(ctx)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("AviraSrv not get client")
		return mas, err
	}

	defer aviraE.BackClient(ctx, client) // 不管扫描是否正确，都要归还 client

	for dig, files := range prepare.LayerFile {
		logging.Get().Info().Str("module", "imagescan").Str("layerDigest", dig).
			Int("fileCnt", len(files)).Msg("AviraSrv")
		for i := range files {
			fi := files[i]
			if !s.FilterAviraScan(ctx, fi) {
				continue
			}
			logging.Get().Debug().Str("module", "imagescan").Str("file", fi).Msg("AviraSrv")
			malware, err := aviraE.DoScanFile(ctx, client.Client, fi)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("AviraSrv")
				continue
			}
			if len(malware) == 0 {
				continue
			}
			// FIXME 不够优雅
			prefix := filepath.Join(s.ScanP.GenRootDir(ctx, prepare.Subtask), GetSimDigest(dig))

			for j := range malware {
				ma := malware[j]
				md5, err := GetFileMd5(fi)
				if err != nil {
					logging.Get().Err(err).Str("module", "imagescan").Str("filename", fi).Msg("AviraSrv GetFileMd5")
					continue
				}

				ans := imagesecTypes.AviraScanResult{
					Filename: fi,
					Hash:     md5,
					Malware:  make([]imagesecTypes.AviraMalware, 0),
					Layer:    GenDigest(dig),
				}
				ans.Malware = append(ans.Malware, imagesecTypes.AviraMalware{
					Type:        ma.Type,
					Name:        ma.Name,
					Description: ma.Desc,
				})

				content, err := os.ReadFile(fi)
				if err != nil {
					logging.Get().Err(err).Str("module", "imagescan").Str("filename", fi).Msg("AviraSrv ReadFile")
					continue
				}

				// /Imagescan/736/data/6653a5467fbd9529586d1ed5cdefd123da0eb329fae6e99ed057aca7a53292d1/fileder/webshell/webserver_type/
				ans.Filename = strings.Replace(ans.Filename, prefix, "", 1)

				res = append(res, ans)

				sendKafka := types.SafeFileToKafka{
					FileMd5:  md5,
					Data:     content,
					Filename: ans.Filename,
				}
				_ = s.SendFileToKafka(ctx, sendKafka)
			}
		}
	}

	mas.Scanned = true

	mas.AviraScanResults = res
	logging.Get().Info().Str("module", "imagescan").Str("scanTask", prepare.Subtask.LogStr()).
		Int("aviraCnt", len(res)).Msg("AviraSrv end")

	return mas, nil
}

func (s *RegImageScan) ScanWebshell(ctx context.Context, prepare *types.PrepareScan) (imagesecTypes.WebshellResults, error) {

	wrs := imagesecTypes.WebshellResults{
		Scanned:         false,
		HmWebshells:     make([]imagesecTypes.HmWebshell, 0),
		HmEngineVersion: imagesecTypes.HmEngineVersion{},
	}
	if os.Getenv("ScanWebshell") == consts.FalseString {
		return wrs, nil
	}
	if prepare == nil || !prepare.Subtask.DeepScan {
		return wrs, nil
	}
	logging.Get().Info().Str("module", "imagescan").Str("scanTask", prepare.Subtask.LogStr()).Msg("ScanWebshell start")
	// 为啥要在这里获取呢？因为如果不开启深度扫描，是不用实例化引擎的
	hme, err := hm.NewScanHM()
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("NewScanHM")
		return wrs, err
	}

	uidMap, _ := ParseEtcPasswd(prepare.EtcPasswdFile)
	gidMap, _ := ParseEtcGroup(prepare.EtcGroupFile)

	ans := make([]imagesecTypes.HmWebshell, 0)

	for i := range prepare.Layers {
		lay := prepare.Layers[i]
		logging.Get().Info().Str("module", "imagescan").Interface("layerPath", lay.UnzipPath).Msg("ScanWebshell")
		wss, err := hme.ScanWebshell(ctx, lay.UnzipPath)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("ScanWebshell")
			continue
		}
		if len(wss) == 0 {
			continue
		}
		for j := range wss {
			ws := wss[j]
			op, err := os.Stat(ws.Filename)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Str("filename", ws.Filename).
					Msg("ScanWebshell ReadFile")
				continue
			}
			// 容器中可能没有 passwd 和 group 文件，且这里也不要求一定有值，所以没有判错
			uid, _ := FileUID(ws.Filename)
			uname := uidMap[uid].Username
			gid, _ := FileUID(ws.Filename)
			gname := gidMap[gid].Name

			ws.Mod = fmt.Sprintf("%s %s %s", op.Mode().String(), uname, gname)

			content, err := os.ReadFile(ws.Filename)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Str("filename", ws.Filename).
					Msg("ScanWebshell ReadFile")
				continue
			}
			sendKafka := types.SafeFileToKafka{
				FileMd5:  ws.MD5,
				Data:     content,
				Filename: strings.Replace(ws.Filename, lay.UnzipPath, "", 1),
			}
			_ = s.SendFileToKafka(ctx, sendKafka)

			ws.Filename = strings.Replace(ws.Filename, lay.UnzipPath, "", 1)
			ans = append(ans, ws)
		}

		logging.Get().Info().Str("module", "imagescan").Str("path", lay.UnzipPath).Str("digest", lay.Digest).
			Int("webshellCnt", len(ans)).Msg("ScanWebshell")
	}

	wrs.HmWebshells = ans
	wrs.Scanned = true
	logging.Get().Info().Str("module", "imagescan").Str("scanTask", prepare.Subtask.LogStr()).
		Int("webshellCnt", len(ans)).Msg("ScanWebshell end")
	return wrs, nil
}

func (s *RegImageScan) SendFileToKafka(ctx context.Context, saveInfo types.SafeFileToKafka) error {
	if len(saveInfo.Data) == 0 {
		logging.Get().Error().Msg("saveInfo file data is empty")
		return nil
	}
	if int64(len(saveInfo.Data)) > s.MaxSingeFileSize {
		logging.Get().Error().Msg("saveInfo file data is too big")
		return nil
	}
	bys, err := json.Marshal(saveInfo)
	if err != nil {
		return err
	}

	err = s.MqWriter.Write(context.Background(), scannermodel.WebshellKafkaTopic, kafka.Message{
		Key:   []byte(scannermodel.WebshellKafkaKey),
		Value: bys,
	})
	if err != nil {
		logging.Get().Err(err).Str("Filename", saveInfo.Filename).Str("FileMd5", saveInfo.FileMd5).Msg("SendFileToKafka")
		return err
	}
	logging.Get().Debug().Int("Data", len(saveInfo.Data)).Str("FileMd5", saveInfo.FileMd5).Msg("SendFileToKafka")
	return nil
}

func (s *RegImageScan) CleanUpScan(ctx context.Context, pre *types.PrepareScan) error {
	if pre == nil {
		s.Log.Info().Msg("not clean up scan data,pre is nil")
		return nil
	}
	if pre.ImageRootDir == "" {
		s.Log.Info().Str("ImageRootDir", pre.ImageRootDir).Msg("not clean up scan data")
		return nil
	}
	_, err := os.Stat(pre.ImageRootDir)
	if err != nil {
		s.Log.Err(err).Str("ImageRootDir", pre.ImageRootDir).Msg("not clean up scan data")
		return err
	}
	if err := os.RemoveAll(pre.ImageRootDir); err != nil {
		s.Log.Err(err).Str("ImageRootDir", pre.ImageRootDir).Msg("not clean up scan data")
		return err
	}
	return nil
}

func (s *RegImageScan) changCacheUrl(im string) (string, error) {
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(im, nameOpts...)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("parse image failed")
		return "", err
	}

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()
	newImage := s.ImageCacheURL + repositoryName + ":" + tag
	return newImage, nil
}

// 对部分文件不进行病毒扫描
// 后续可能增加逻辑
func (s *RegImageScan) FilterAviraScan(ctx context.Context, fn string) bool {
	fi, err := os.Stat(fn)
	if err != nil {
		return false
	}
	if fi.Size() == 0 {
		return false
	}
	if fi.Size() > s.MaxSingeFileSize {
		return false
	}
	if fi.IsDir() {
		return false
	}
	if !fi.Mode().IsRegular() {
		return false
	}
	return true
}

func GenDigest(dig string) string {
	if strings.Contains(dig, "sha25:") {
		return dig
	}
	return fmt.Sprintf("sha256:%s", dig)
}

func GetSimDigest(dig string) string {
	dig = strings.Replace(dig, "sha256:", "", 1)
	return dig
}
