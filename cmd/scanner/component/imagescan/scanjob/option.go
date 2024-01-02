package scanjob

type Option func(o *RegImageScan)

type ScanConfig struct {
	MaxSingeFileSize int64
	// 主集群会控制下发任务的数量，但是各子集群的配置可能不一样，所以子集群也需要控制并发度
	ScanEnginNum          int64
	ImageCacheURL         string
	CacheCleanPerInterval int64
	SubtaskParallel       int64 // 允许同时间执行的任务数(后期应该做成界面可配置功能)
}

func WithMaxSingeFileSize(op int64) Option {
	return func(o *RegImageScan) {
		o.Config.MaxSingeFileSize = op
	}
}

func WithScanEnginNum(op int64) Option {
	return func(o *RegImageScan) {
		o.Config.ScanEnginNum = op
	}
}

func WithImageCacheURL(op string) Option {
	return func(o *RegImageScan) {
		o.Config.ImageCacheURL = op
	}
}

func WithSubtaskParallel(op int64) Option {
	return func(o *RegImageScan) {
		o.Config.SubtaskParallel = op
	}
}
