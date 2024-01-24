package hm

var (
	DefaultHmScanIncludeFileExt = []string{
		".php", ".php5", ".php4", ".asp", ".aspx", ".asmx", ".ashx", ".jsp",
		".jspa", ".jspx", ".jspf", ".cer", ".htaccess",
	}
	DefaultHmScanExcludeFileExt = []string{
		".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".doc", ".docx", ".ppt", ".pptx", ".csv", ".xls", ".xlsx", ".rpm", ".xml", ".map",
	}
	defaultHmScanConfig = HmScanConfig{
		Include: DefaultHmScanIncludeFileExt,
		Exclude: DefaultHmScanExcludeFileExt,
	}
)

// HmScanConfig define what types of file will be scanned
type HmScanConfig struct {
	Exclude []string `yaml:"exclude"`
	Include []string `yaml:"include"` // e.g.[".php", ".jsp"]
}

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
