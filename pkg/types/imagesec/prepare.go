package imagesec

import (
	"strings"

	"github.com/docker/distribution/manifest/schema2"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageLayer struct {
	Digest          string // 层级 digest
	OriginalTarFile string // 文件服务器的tar,多个镜像共用
	LayerFilePath   string // 该层文件的绝对路径
	TarFilename     string // 解圧前复制该文件
	PreFix          string // 文件的前缀，去除这个，才是镜像中的文件路径
	Ready           bool   // 文件是否已准备好
}

func (vi *ImageLayer) ContainerFilename(file string) string {
	if vi.PreFix != "" {
		file = strings.TrimPrefix(file, vi.PreFix)
	}

	if !strings.HasPrefix(file, "/") {
		return "/" + file
	}
	return file
}

type PrepareScan struct {
	Subtask       ScanSubTask
	Layers        map[string]*ImageLayer // 层级信息
	TaskRootDir   string                 // 扫描完成后删除该目录
	UserDockerCli bool                   // 是否使用了 docker pull 命令，如果使用该命令，就只能扫描 PKG
	Errors        []error                `json:"-"`
	LayerChan     chan *ImageLayer
}

type ManifestV2AndV1 struct {
	V2 *schema2.DeserializedManifest
	V1 *model.ManifestV1
}

func GenLayerDigest(v *ManifestV2AndV1) []string {

	res := make([]string, 0)
	if v.V2 != nil {
		// 一定要加这个，不然不能扫描，后面再去弄明白
		// 因为这一个文件是镜像inspect 的结果，在扫描调用接口时会用到
		// 这个文件是.tar结尾，但他却是一个文本文件，可以用 cat 命令查看
		res = append(res, v.V2.Manifest.Config.Digest.String())

		for i := range v.V2.Layers {
			res = append(res, v.V2.Layers[i].Digest.String())
		}
		return res
	}
	if v.V1 != nil {
		for i := range v.V1.HistoryV1 {
			vv := v.V1.HistoryV1[i]
			if !vv.Throwaway {
				res = append(res, "sha256:"+vv.LayerDigest)
			}
		}
		return res
	}
	return res
}
