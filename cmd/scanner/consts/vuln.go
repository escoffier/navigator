package consts

const (
	VulnLanguageGO = "go"
)

const (
	SeverityCRITICALString = "CRITICAL"
	SeverityHIGHString     = "HIGH"
	SeverityMEDIUMString   = "MEDIUM"
	SeverityLOWString      = "LOW"
	SeverityUNKNOWNString  = "UNKNOWN"
)

const (
	SeverityCRITICAL = 5
	SeverityHIGH     = 4
	SeverityMEDIUM   = 3
	SeverityLOW      = 2
	SeverityUNKNOWN  = 1
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
