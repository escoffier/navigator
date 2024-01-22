package kafkaAsset

import (
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageQueue struct {
	WG            sync.Locker
	Images        []uint64
	LastUpdate    int64 // 单分毫秒
	CheckInterval int64 // 单分毫秒
}

func NewImageQueue(in int64) *ImageQueue {
	s := &ImageQueue{
		WG:            &sync.Mutex{},
		Images:        make([]uint64, 0),
		CheckInterval: in,
		LastUpdate:    time.Now().UnixMilli(),
	}
	return s
}

func (vi *ImageQueue) Add(im *imagesecModel.Image) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	vi.Images = append(vi.Images, im.UniqueID)
	vi.LastUpdate = time.Now().UnixMilli()
}

func (vi *ImageQueue) NeedCreateScanTask() bool {
	vi.WG.Lock()
	defer vi.WG.Unlock()

	if len(vi.Images) >= consts.DefaultSubtaskCntBySingeTask {
		return true
	}
	if time.Now().UnixMilli()-vi.LastUpdate >= vi.CheckInterval && len(vi.Images) > 0 {
		return true
	}
	return false
}

func (vi *ImageQueue) GetImages() []uint64 {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	ans := make([]uint64, 0)
	ans = append(ans, vi.Images...)

	vi.Images = make([]uint64, 0)
	vi.LastUpdate = time.Now().UnixMilli()
	return ans
}
