package imagesec

import (
	"encoding/json"
	"strconv"
	"strings"

	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageWithCorrelateData struct {
	ImageList         model.ImageList
	ImageBaseResponse ImageBaseResponse
	Sensitive         []*model.ImageSensitiveFile
	SensitiveCnt      int64
	Webshell          []*scannermodel.Webshell
	WebshellCnt       int64
	Env               []*model.ImageEnv
	EnvCnt            int64
	Vuln              []*model.Vuln
	VulnCnt           int64
	Software          []*model.ImageSoftware
	SoftwareCnt       int64
	License           []string // 异常的license
	Virus             []*model.ImageVirus
	VirusCnt          int64
	BaseImages        []*ImageBaseResponse // 基础镜像列表
	BaseImageCnt      int64
	AppImages         []*ImageBaseResponse // 应用镜像列表
	AppImageCnt       int64
	Container         []*ContainerResources
	SubTask           []model.SubTask
	SubTaskCnt        int64
	Registry          *Registry
}

func imageListToImage(im model.ImageList) Image {
	img := Image{
		ID:            im.ID,
		ImageFromType: ImageFromRegistry,
		Host:          im.Library,
		Repo:          im.FullRepoName,
		Tag:           im.Tags,
		Digest:        im.Digest,
		Size:          int64(im.Size),
		User:          im.GetBootUser(),
		Flag:          im.Flag,
		ImageUUID:     im.ImageUUID,
		RegID:         im.RegistryID,
		Heartbeat:     im.UpdatedAt.UnixMilli(),
		CreatedAt:     util.GetTimeUnixMilli(&im.CreatedAt),
		UpdatedAt:     util.GetTimeUnixMilli(&im.UpdatedAt),
		OSJson:        im.OS,
	}

	scanOS := types.OS{}
	if err := json.Unmarshal([]byte(im.OS), &scanOS); err == nil {
		img.OS = scanOS
	}
	img.UniqueID = img.GenUniqueID()
	img.ImageUUID = im.GenImageUUID()

	return img
}

func convertSensitiveFile(ss []*model.ImageSensitiveFile) []*SensitiveFile {
	ans := make([]*SensitiveFile, 0)
	for i := range ss {
		ans = append(ans, &SensitiveFile{
			ID:            ss[i].ID,
			UniqueID:      ss[i].UniqueID,
			Filename:      ss[i].Name,
			DescriptionEn: ss[i].DescriptionEn,
			DescriptionZh: ss[i].DescriptionZh,
			CreatedAt:     ss[i].CreatedAt,
			UpdatedAt:     ss[i].UpdatedAt,
		})
	}
	return ans
}

func convertMalware(ss []*model.ImageVirus) []*Malware {
	ans := make([]*Malware, 0)
	for i := range ss {
		ans = append(ans, &Malware{
			ID:        ss[i].ID,
			UniqueID:  ss[i].UniqueID,
			Name:      ss[i].Name,
			Filename:  ss[i].Filename,
			Filepath:  ss[i].Filepath,
			CreatedAt: ss[i].CreatedAt,
			UpdatedAt: ss[i].UpdatedAt,
		})
	}
	return ans
}

func convertSubtask(ss []model.SubTask) []*ImageScanSubTask {
	ans := make([]*ImageScanSubTask, 0)
	for i := range ss {
		ans = append(ans, &ImageScanSubTask{
			ID:         ss[i].ID,
			TaskID:     ss[i].TaskID,
			StartedAt:  util.GetTimeUnixMilli(ss[i].StartedAt),
			FinishedAt: util.GetTimeUnixMilli(ss[i].FinishedAt),
			CreatedAt:  util.GetTimeUnixMilli(&(ss[i].CreatedAt)),
			UpdatedAt:  util.GetTimeUnixMilli(&(ss[i].UpdatedAt)),
		})
	}
	return ans
}

func convertImageEnv(ss []*model.ImageEnv) []*ImageEnv {
	ans := make([]*ImageEnv, 0)
	for i := range ss {
		ans = append(ans, &ImageEnv{
			ID:           ss[i].ID,
			UniqueID:     ss[i].UniqueID,
			Key:          ss[i].Key,
			Value:        ss[i].Value,
			PolicyDetect: PolicyDetect{Exception: !ss[i].Normal},
			CreatedAt:    ss[i].CreatedAt,
			UpdatedAt:    ss[i].UpdatedAt,
		})
	}
	return ans
}

func convertWebshell(ss []*scannermodel.Webshell) []*WebshellView {
	ans := make([]*WebshellView, 0)
	for i := range ss {
		after := &WebshellView{
			ID:          ss[i].ID,
			UniqueID:    0,
			Filename:    ss[i].FileName,
			FileType:    ss[i].FileType,
			Size:        util.ParseByteSize(int64(ss[i].FileSize)),
			MD5:         ss[i].FileMd5,
			Mod:         Mod{}, // 数据库:"-rw-rw-r--(用户名:root 用户组名:root)"  (用到时再解析)
			Code:        make([]WebshellCode, 0),
			RiskLevel:   strings.ToLower(ss[i].Level),
			Description: ss[i].Description,
			CreatedAt:   ss[i].CreatedAt,
			UpdatedAt:   ss[i].UpdatedAt,
			CodeJSON:    ss[i].MaliciousData,
		}

		// home/webshell/SS.PhP
		split := strings.Split(ss[i].FileName, "/")
		if len(split) > 1 {
			after.Filename = split[len(split)-1]
			after.Filepath = strings.Join(split[:len(split)-1], "/")
		}
		if after.Filepath != "" {
			after.Filepath = after.Filepath + "/"
		}

		split3 := strings.Split(ss[i].FileType, ".")
		if len(split3) >= 2 {
			after.FileType = split3[len(split3)-1]
		}

		// 数据库： "[{"Name":"rule_ssdeep_156","Offset":0,"Data":"MTkyOjJ5NzNjWWdTZkRSSXFvTy9RUVFXUStldHJaNThZZi9ZMTpMN01RUVFRV1ErZXR0NThZOA==","line_no":0}]"
		hm := make([]hMWebshellCode, 0)
		if ss[i].MaliciousData != "" {
			if err := json.Unmarshal([]byte(ss[i].MaliciousData), &hm); err != nil {
				hm = make([]hMWebshellCode, 0)
			}
		}
		for j := range hm {
			after.Code = append(after.Code, WebshellCode{
				Name:   hm[j].Name,
				Offset: hm[j].Offset,
				Data:   ParseWebshellCode(hm[j].Data),
				LineNo: hm[j].LineNo,
			})
		}

		ans = append(ans, after)
	}

	return ans
}

func convertPkg(ss []*model.ImageSoftware) []*Pkg {
	ans := make([]*Pkg, 0)
	for i := range ss {
		pkg := &Pkg{
			ID:        ss[i].ID,
			UniqueID:  ss[i].UniqueID,
			Name:      ss[i].Name,
			Version:   ss[i].Version,
			CreatedAt: ss[i].CreatedAt,
			UpdatedAt: ss[i].UpdatedAt,
			License:   ss[i].License,
			DependsOn: make([]string, 0),
		}

		if util.ExistBit1(ss[i].Flag, FlagHasExceptionPKG) {
			pkg.PolicyDetect.Exception = true
		}
		if util.ExistBit1(ss[i].Flag, FlagHasExceptionPkgLicense) {
			pkg.PolicyDetect.ExceptionPkgLicense = true
		}

		ans = append(ans, pkg)
	}
	return ans
}

func ConvertVuln(ss []*model.Vuln) []*VulnView {
	ans := make([]*VulnView, 0)
	for i := range ss {

		ss[i].Deserialize()

		vu := &VulnView{
			ID:             ss[i].ID,
			UniqueID:       ss[i].UniqueVuln,
			PkgUniqueID:    0, // 老接口用不到
			Name:           ss[i].Name,
			PkgName:        ss[i].PkgName,
			PkgVersion:     ss[i].PkgVersion,
			CnnvdName:      ss[i].CnnvdName,
			PkgRelease:     ss[i].Namespace,
			Description:    ss[i].Description,
			References:     ss[i].Link,
			CweIds:         make([]string, 0),
			SeverityInt:    ss[i].SeverityInt,
			Severity:       GetSeverityEN(ss[i].SeverityInt),
			Flag:           ss[i].Flag,
			AttackPath:     ss[i].Attr["AV"],
			AttackPathView: GetVulnAVView(LangZh)[ss[i].Attr["AV"]],
			Class:          ss[i].Class,
			ClassView:      ss[i].GetVulnClassView(),
			KernelVuln:     util.ExistBit1(ss[i].Flag, VulnFlagKernel),
			Language:       ss[i].Language,
			FixedVersion:   ss[i].FixedBy,
			Frame:          ss[i].Frame,
			Target:         ss[i].Target,
			PosAttr:        ss[i].CvssMap,
			CreatedAt:      ss[i].CreatedAt.UnixMilli(),
			UpdatedAt:      ss[i].UpdatedAt.UnixMilli(),
			Attr:           ss[i].Attr,
		}
		if ss[i].Metadata != nil {
			if len(ss[i].Metadata.CNVDs) > 0 {
				vu.Title = ss[i].Metadata.CNVDs[0].Title
			}
			vu.CnnvdFixSuggestion = ss[i].Metadata.CNNVDs.FixSuggestion

			vu.CVSSV2Score, _ = strconv.ParseFloat(ss[i].Metadata.CVSS.CVSSv2Score, 64)
			vu.CVSSV3Score, _ = strconv.ParseFloat(ss[i].Metadata.CVSS.CVSSv3Score, 64)
			vu.CVSSV3Vector = ss[i].Metadata.CVSS.CVSSv3Vector
			vu.CVSSV2Vector = ss[i].Metadata.CVSS.CVSSv2Vector
		}

		ans = append(ans, vu)
	}

	return ans
}

func (iws *ImageWithCorrelateData) Adapt() *ImageWithCorrelateData2 {
	ans := &ImageWithCorrelateData2{
		Image:        imageListToImage(iws.ImageList),
		Sensitive:    convertSensitiveFile(iws.Sensitive),
		SensitiveCnt: iws.SensitiveCnt,
		WebshellView: convertWebshell(iws.Webshell),
		WebshellCnt:  iws.WebshellCnt,
		Env:          convertImageEnv(iws.Env),
		EnvCnt:       iws.EnvCnt,
		Vuln:         ConvertVuln(iws.Vuln),
		VulnCnt:      iws.VulnCnt,
		Pkg:          convertPkg(iws.Software),
		PkgCnt:       iws.SoftwareCnt,
		Malware:      convertMalware(iws.Virus),
		MalwareCnt:   iws.VirusCnt,
		BaseImages:   iws.BaseImages,
		BaseImageCnt: iws.BaseImageCnt,
		AppImages:    iws.AppImages,
		AppImageCnt:  iws.AppImageCnt,
		// Container:    iws.Container,
		ScanSubTask: convertSubtask(iws.SubTask),
		SubTaskCnt:  iws.SubTaskCnt,
		Registry:    iws.Registry,
	}
	return ans
}
