package scanjob

type Option func(o *RegImageScan)

type ScanConfig struct {
	MaxSingeFileSize      int64
	ImageCacheURL         string
	HMExt                 map[string]bool // HM默认扫描的后缀名
	CacheCleanPerInterval int64
	SubtaskParallel       int64 // 允许同时间执行的任务数(后期应该做成界面可配置功能)
}

func WithMaxSingeFileSize(op int64) Option {
	return func(o *RegImageScan) {
		o.Config.MaxSingeFileSize = op
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
