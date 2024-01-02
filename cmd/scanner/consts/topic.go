package consts

const (
	NodeImageTopic = "node_image_asset"
	NodeImageGroup = "node_image_asset_group"
	NodeImageKey   = "node_image_asset_key"

	ScanInstanceTopic = "scan_instance"
	ScanInstanceGroup = "scan_instance_group"
	ScanInstanceKey   = "scan_instance_key"

	NodeImageScanResultTopic = "node_image_scan_result"
	NodeImageScanResultGroup = "node_image_scan_result_group"
	NodeImageScanResultKey   = "node_image_scan_result_key"

	WebshellKafkaTopic   = "ivan_scanner_webshell"
	WebshellKafkaKey     = "ivan_scanner_webshell_key"
	WebshellKafkaGroupID = "ivan_scanner_webshell_scanner"
	WebshellSize         = (1 << 20) * 10
)
