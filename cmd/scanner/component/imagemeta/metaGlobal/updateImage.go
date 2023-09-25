package metaGlobal

import (
	"sync"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 为啥要新建这么一个文件夹呢
// 因为不想这些包变量直接暴露
// 代码有点乱，后期改进

var (
	imagePrepareData *PrepareData
	updateChan       *ImageUpdateChan
)

type ImageUpdateChan struct {
	AddRegImageChan    chan *imagesecModel.Image // 更新节点镜像是否在仓库中
	DeleteRegImageChan chan *imagesecModel.Image // 更新节点镜像是否在仓库中
}

type PrepareData struct {
	WG               sync.Mutex
	ImagePrepareData imagesecModel.ImagePrepareData
}

func (vi *PrepareData) GetImagePrepareData() *imagesecModel.ImagePrepareData {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	return vi.ImagePrepareData.DeepCopy()
}

func (vi *PrepareData) SetNodeGroupProject(node []imagesecModel.GroupProject) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	imagePrepareData.ImagePrepareData.NodeGroupProject = node
}

func (vi *PrepareData) SetRegGroupProject(reg []imagesecModel.GroupProject) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	imagePrepareData.ImagePrepareData.RegGroupProject = reg
}

func (vi *PrepareData) SetRegImageOverView(reg imagesecModel.SecurityStatistic) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	imagePrepareData.ImagePrepareData.RegImageOverView = reg
}

func (vi *PrepareData) SetNodeImageOverView(node imagesecModel.SecurityStatistic) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	imagePrepareData.ImagePrepareData.NodeImageOverView = node
}

func GetImageUpdateChan() *ImageUpdateChan {
	if updateChan != nil {
		return updateChan
	}
	updateChan = &ImageUpdateChan{
		AddRegImageChan:    make(chan *imagesecModel.Image),
		DeleteRegImageChan: make(chan *imagesecModel.Image),
	}
	return updateChan
}

func GetPrepareData() *PrepareData {
	if imagePrepareData != nil {
		return imagePrepareData
	}
	imagePrepareData = &PrepareData{
		WG: sync.Mutex{},
		ImagePrepareData: imagesecModel.ImagePrepareData{
			RegGroupProject:   make([]imagesecModel.GroupProject, 0),
			NodeGroupProject:  make([]imagesecModel.GroupProject, 0),
			RegImageOverView:  imagesecModel.SecurityStatistic{},
			NodeImageOverView: imagesecModel.SecurityStatistic{},
		},
	}
	return imagePrepareData
}
