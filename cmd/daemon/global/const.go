package global

const (
	MountPathInContainer        = "/host"                // host path mount in container,eg.[container]/host/var/lib/docker->[host]/var/lib/docker
	WorkingDir                  = "/var/lib/tensor"      // dp working dir
	DmSetupDir                  = "dmsetup"              // dmsetup dir which contain some device info
	DaemonRunModeEnv            = "DAEMON_RUN_MODE"      // dp run mode env
	DaemonRunModeLocal          = "run_in_local"         // for local test
	DefaultDevMapperSnapSectors = "20971520"             // default sector number,equal to 10GB size
	CustomSnapSectorNumberEnv   = "DEVMAPPER_SECTOR_NUM" // custom devicemapper setors
	DpScanModeEnv               = "CIA_SCAN_MODE"        // whitelist scan mode
	DpScanModeImageTar          = "IMAGE_TAR"            // generate whitelist by export image tar
)
