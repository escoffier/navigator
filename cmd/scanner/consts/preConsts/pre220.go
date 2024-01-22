// 在这个包内定义常

package preConsts

import (
	"fmt"
)

const (
	TrustedImage = 1

	YesString = "y"
	NoString  = "n"
)

const EncryptPasswordKey = "talkerss"

const (
	IntervalDay  = "day"
	IntervalHour = "hour"
)

const TimeFormatWithHour = "2006-01-02 15"
const TimeFormatWithDay = "2006-01-02"

const (
	ValidateCreate = "create"
	ValidateUpdate = "update"
)

const (
	IsTrustedImageString  = "1"
	NotTrustedImageString = "0"
	IsTrustedImage        = 1
	NotTrustedImage       = 0
)

var ErrNotNodeImage = fmt.Errorf("not find node info")

const SecureImageRiskScore = 60

const (
	Unknown = iota
	Pending
	InProgress
	End
	Pause
	Terminate
)

// image(subtask) scan status
const (
	ImageScanUnknown = iota
	ImageScanPending
	ImageScanInProgress
	ImageScanSuccess
	ImageScanFailed
	ImageNotScan
	ImageScanAdapt = 21 // 2.19版本的数据已经适配到2.20之后的版本
)

const (
	FullScan = iota // 全量扫描
)

// task trigger type
const (
	UnknownTrigger = iota
	CiCdTrigger
	VulDataUpdateTrigger
	VirusDataUpdateTrigger
	ScheduleTrigger
	ImageSyncTrigger
	ManualTrigger
)

const SubTaskBatchInsertCount = 200

// 后面做仓库镜像重构时移出
const (
	UniqueVulnFamat      = "%s-%s-%s" // vn.Name, vn.PkgName, vn.PkgVersion
	UniqueVirusFamat     = "%s-%s-%s"
	UniqueSensitiveFamat = "%s-%s"
	UniqueSoftwareFamat  = "%s-%s"
	UniqueENVFamat       = "%s-%s-%t"
	UniqueWebshellFamat  = "%s-%s-%s"
	UniqueImageFamat     = "%s-%s-%d-%d" // im.FullRepoName, im.Tags, im.ImageFromType, im.RegID))
)

const (
	EnvIsAbnormal = 1
)

const (
	CreateOnlineImageTempTableSql = `
create temporary table if not exists ivan_scanner_online_image
(
    id         bigint primary key auto_increment,
    image_id   bigint,
    image_uuid bigint,
    index (image_id)
) engine = innodb;
`

	InsertOnlineImageTempTableSql string = `
insert into ivan_scanner_online_image (image_id, image_uuid)
SELECT a.id         as image_id,
       a.image_uuid as image_uuid
FROM ivan_scanner_image_list a
         join ivan.ivan_assets_containers b on a.image_uuid = b.image_uuid
WHERE b.status = 0 ;
`

	SearchOnlineImageVulnSql string = `
SELECT *
FROM ivan_scanner_vulns
WHERE unique_vuln IN (SELECT distinct a.unique_vuln
                      FROM ivan_scanner_vuln_images a
                               join ivan_scanner_online_image b on a.image_id = b.image_id)
`

	DropOnlineImageTempTableSql string = `drop temporary table if exists ivan_scanner_online_image;`
)
