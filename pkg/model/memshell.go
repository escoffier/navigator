package model

const (
	MemshellConfigmapValueSplitter = "/"
	MemshellScanSyncConfigMapName  = "memshell-scan-sync"
	MemshellScanSyncKeyTemplate    = "scan-%d"        // scan-resource_uuid
	MemshellScanSyncValueTemplate  = "%s/%s/%s/%s/%d" //ClusterKey,Namespace,ResourceKind,Resource, timestamp
	MemshellConfigMapLabel         = "app=memshell-cm"
)
