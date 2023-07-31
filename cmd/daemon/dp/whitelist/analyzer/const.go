package analyzer

type Type string

const (
	TypeOverlay2     Type = "overlay2"     // type name should be same as docker driver's name
	TypeDeviceMapper Type = "devicemapper" // type name should be same as docker driver's name
	TypeImageTar     Type = "image-tar"
	TypeOverlayCRIO  Type = "overlaycrio"
)

type ExecFiles map[string]string
