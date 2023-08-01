package consts

const (
	NodeTrivyDBPath               = "/node/db/trivy.db"
	NodeCustomDBPath              = "/node/db/custom.db"
	NodeVulnDir                   = "/node/db"
	WebshellFileDir               = "webshell"
	MaxInprogressSubtaskPerNode   = 5
	MaxInprogressTask             = 5
	DefaultSendSubtaskBatchSize   = 5
	MaxRetryCnt                   = 10
	MillisecondPerDay             = 24 * 60 * 60 * 1000
	DefaultSubScannerTaskParallel = 4
	DefaultScanTimeout            = 30 // 30分钟
)
