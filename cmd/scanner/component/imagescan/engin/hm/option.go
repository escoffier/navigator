package hm

type Option func(*ScanHM)

func WithBinCnt(cnt int64) Option {
	return func(hm *ScanHM) {
		hm.BinCnt = cnt
	}
}

func WithHmRootPath(pa string) Option {
	return func(hm *ScanHM) {
		hm.HmRootPath = pa
	}
}

func WithScanTimeout(to int64) Option {
	return func(hm *ScanHM) {
		hm.ScanTimeout = to
	}
}
