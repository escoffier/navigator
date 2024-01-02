package dbmanager

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type NodeInfoQueue struct {
	nodeInfoDal    imagesecStore.NodeInfoDal
	scanVersionDal imagesecStore.ScanDbMetaDal
}

func (s *NodeInfoQueue) GenDBChan(ctx context.Context) chan imagesecModel.ScanConfigDB {
	return nil
}

func (s *NodeInfoQueue) GenSenChan() chan imagesecModel.NodeInfo {
	return nil
}

func (s *NodeInfoQueue) GetZIP() {

}

func (s *NodeInfoQueue) GetLatestDBVersion(ctx context.Context) (types.LatestDBVersion, error) {
	return types.LatestDBVersion{}, nil
}
