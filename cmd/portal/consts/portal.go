package consts

const (
	Svn           = "Svn"
	TFS           = "TFS"
	Gerrit        = "Gerrit"
	Mercurial     = "Mercurial"
	Coding        = "Coding"
	Artifactory   = "Artifactory"
	Firefly       = "Firefly"
	DefaultExpire = "2099-01-01 00:00:00"

	ProjectUrlHeadHttps       = 0
	ProjectGitAuthMethodToken = 1
	SourceCheckPullWayToken   = 2
	DefaultScanTimeout        = 60 * 5
	DefaultBatchSize          = 10
)

const (
	ModelSourceCheck = "sourceCheck"
	ModelCodesec     = "codesec"
)

const (
	ProjectGitTypeGitLab = 1
	ProjectGitTypeGitHub = 2
	ProjectGitTypeGitee  = 3
	GitTypeGit           = "git"
	GitlabApiVersionV3   = "V3"
	GitlabApiVersionV4   = "V4"

	SourceCheckProjectTypeGit = "1"
)

const (
	DuplicateKey      = "Duplicate"
	PortalAdminName   = "portalAdmin"
	PortalProjectExit = "已存在"
)

const SourceCheckStatusOK = 1

const (
	ScanStatusNotScan  = "not_scan"
	ScanStatusScanning = "scanning"
	ScanStatusSuccess  = "success"
	ScanStatusFailed   = "failed"
	ScanSuccessMsg     = "成功"
	ScanFinishMsg      = "完成"
	ScanFailedMsg      = "失败"
	ScanTerMsg         = "中止"
)

const (
	ScanFailedTimeout         = "扫描超时"
	ScanFailedCantGetProgress = "无法获取扫描进度"
	ScanFailedCantGetResult   = "无法获取扫描结果"
)

/*
{
            "dicCode": "0",
            "dicName": "未检测",
            "order": 1
        },
        {
            "dicCode": "1",
            "dicName": "检测中",
            "order": 2
        },
        {
            "dicCode": "2",
            "dicName": "已检测",
            "order": 3
        },
        {
            "dicCode": "3",
            "dicName": "待检测",
            "order": 4
        },
        {
            "dicCode": "4",
            "dicName": "检测失败",
            "order": 5
        },
        {
            "dicCode": "5",
            "dicName": "下载中",
            "order": 6
        },
        {
            "dicCode": "6",
            "dicName": "下载完成",
            "order": 7
        },
        {
            "dicCode": "7",
            "dicName": "待下载",
            "order": 8
        },
        {
            "dicCode": "8",
            "dicName": "下载失败",
            "order": 9
        },
        {
            "dicCode": "13",
            "dicName": "待刷新",
            "order": 14
        },
        {
            "dicCode": "14",
            "dicName": "刷新中",
            "order": 15
        },
        {
            "dicCode": "9",
            "dicName": "暂停中",
            "order": 10
        },
        {
            "dicCode": "10",
            "dicName": "检测暂停",
            "order": 11
        },
        {
            "dicCode": "11",
            "dicName": "停止中",
            "order": 12
        },
        {
            "dicCode": "12",
            "dicName": "检测停止",
            "order": 13
        }
*/

const (
	SourceCheckScanStateNotChecked     = 0  // 未检测
	SourceCheckScanStateChecking       = 1  // 检测中
	SourceCheckScanStateChecked        = 2  // 已检测
	SourceCheckScanStateToBeChecked    = 3  // 待检测
	SourceCheckScanStateCheckFailed    = 4  // 检测失败
	SourceCheckScanStateDownloading    = 5  // 下载中
	SourceCheckScanStateDownloadDone   = 6  // 下载完成
	SourceCheckScanStateToBeDownloaded = 7  // 待下载
	SourceCheckScanStateDownloadFailed = 8  // 下载失败
	SourceCheckScanStatePausing        = 9  // 暂停中
	SourceCheckScanStatePaused         = 10 // 检测暂停
	SourceCheckScanStateStopping       = 11 // 停止中
	SourceCheckScanStateStopped        = 12 // 检测停止
	SourceCheckScanStateToBeRefreshed  = 13 // 待刷新
	SourceCheckScanStateRefreshing     = 14 // 刷新中
)
