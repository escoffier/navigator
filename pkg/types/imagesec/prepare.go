package imagesec

import (
	"os"
	"strings"

	"github.com/docker/distribution/manifest/schema2"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageLayer struct {
	Digest          string // 层级 digest
	Size            int64  // 层级大小
	OriginalTarFile string // 文件服务器的tar,多个镜像共用
	LayerFilePath   string // 该层文件的绝对路径,只有开启深度扫描时才有用
	TarFilename     string // 解圧前复制该文件,只有开启深度扫描时才有用
	PreFix          string // 文件的前缀，去除这个，才是镜像中的文件路径
	NotReady        bool   // 文件是否已准备好
	NeedPull        bool   // 需要下载
	NeedExtract     bool   // 需要解压
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

type FileFilter func(info os.FileInfo) bool

type PrepareScan struct {
	Subtask       ScanSubTask
	Layers        map[string]*ImageLayer // 层级信息
	TaskRootDir   string                 // 扫描完成后删除该目录
	UserDockerCli bool                   // 是否使用了 docker pull 命令，如果使用该命令，就只能扫描 PKG
	Errors        []error                `json:"-"`
	FileFilter    FileFilter
	ImageManifest ManifestV2AndV1
}

func (vi *PrepareScan) DeepCopy() *PrepareScan {
	return &PrepareScan{
		Subtask:       vi.Subtask,
		Layers:        vi.Layers,
		TaskRootDir:   vi.TaskRootDir,
		UserDockerCli: vi.UserDockerCli,
		Errors:        vi.Errors,
	}
}

func (vi *PrepareScan) ReplaceLayer(ly *ImageLayer) {
	vi.Layers = make(map[string]*ImageLayer)
	vi.Layers[ly.Digest] = ly
}

type ManifestV2AndV1 struct {
	V2          *schema2.DeserializedManifest
	V1          *model.ManifestV1
	ImageDigest string
}

func (v ManifestV2AndV1) GenImageLayer() []*ImageLayer {

	res := make([]*ImageLayer, 0)
	if v.V2 != nil {
		// 一定要加这个，不然不能扫描，后面再去弄明白
		// 因为这一个文件是镜像inspect 的结果，在扫描调用接口时会用到
		// 这个文件是.tar结尾，但他却是一个文本文件，可以用 cat 命令查看
		// 需要下载到本地
		// res = append(res, &ImageLayer{
		// 	Digest: v.V2.Manifest.Config.Digest.String(),
		// })

		for i := range v.V2.Layers {
			res = append(res, &ImageLayer{
				Digest: v.V2.Layers[i].Digest.String(),
				Size:   v.V2.Layers[i].Size,
			})
		}
		return res
	}
	if v.V1 != nil {
		for i := range v.V1.HistoryV1 {
			vv := v.V1.HistoryV1[i]
			if !vv.Throwaway {
				res = append(res, &ImageLayer{
					Digest: "sha256:" + vv.LayerDigest,
					Size:   v.V2.Layers[i].Size,
				})
			}
		}
		return res
	}

	return res
}

type ImageLayers []*ImageLayer

func (vi ImageLayers) Len() int {
	return len(vi)
}

func (vi ImageLayers) Less(i, j int) bool {
	return vi[i].Size > vi[j].Size
}

func (vi ImageLayers) Swap(i, j int) {
	vi[i], vi[j] = vi[j], vi[i]
}
