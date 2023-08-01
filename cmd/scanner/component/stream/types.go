package imagesecStream

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type RegistryValidator interface {
	ValidateRegistry(ctx context.Context, reg imagesecModel.Registry) error
}

type ScanSubtaskReceiver interface {
	ReceiveScanSubtask(ctx context.Context, subtask imagesecTypes.ScanSubTask) error
}

type ImageSyncer interface {
	SyncImage(ctx context.Context, task imagesecModel.ImageSyncTask) string
}

type RpcPong struct {
	ImageSecResp *pb.ImageSecResp
	Stream       rpcstream.Stream
	RegID        string
}

func GetRpcType(ty pb.ImageSecReqType) string {
	switch ty {
	case pb.ImageSecReqType_RegistryImageScan:
		return "registryImageScan"
	case pb.ImageSecReqType_RegistryHealthyCheck:
		return "registryHealthyCheck"
	case pb.ImageSecReqType_RegistryImageSync:
		return "registrySyncImage"
	case pb.ImageSecReqType_NodeImageScan:
		return "nodeImageScan"
	}
	return ""
}
