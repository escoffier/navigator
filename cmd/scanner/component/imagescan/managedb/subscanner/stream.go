package subscanner

import (
	"context"
	"fmt"
	"os"

	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type UpdateDBService interface {
	UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) error
}

type SubScannerHandler struct {
	UpdateDBService UpdateDBService
}

func NewSubScannerHandler(updateDBSrv UpdateDBService) *SubScannerHandler {
	return &SubScannerHandler{UpdateDBService: updateDBSrv}
}

func (vi *SubScannerHandler) OnCreate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
	req := msg.(*pb.ImageSecReq)
	msgType := req.ImageSecReqType
	msgID := req.MsgID
	logging.Get().Info().Str("module", "imagescan").Str("msgID", msgID).Int32("type", int32(msgType)).Msg("SubScannerHandler receive grpc msg")

	switch req.ImageSecReqType {
	case pb.ImageSecReqType_TiDBUpdate:
	case pb.ImageSecReqType_SyncResult:
	case pb.ImageSecReqType_SyncConfig:
	case pb.ImageSecReqType_AviraDBUpdate:
		_ = vi.saveAviraDB(s, reqID, req.Payload)
	default:
		logging.Get().Error().Int32("type", int32(msgType)).Msg("not support msg type")
	}
}

func (vi *SubScannerHandler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-read not implement")
}

func (vi *SubScannerHandler) OnUpdate(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-update not implement")
}

func (vi *SubScannerHandler) OnDelete(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-delete not implement")
}

func (vi *SubScannerHandler) saveAviraDB(s rpcstream.Stream, reqID string, payload []byte) error {

	aviraDBPathInfo := types.GetAviraDBPathInfo()

	logging.Get().Debug().Str("module", "imagescan").Str("path", aviraDBPathInfo.UpdatePath).Msg("sub scanner start save avira db")

	saveFunc := func() error {
		var err error

		defer func() {
			resp := &pb.ImageSecResp{}
			if err != nil {
				resp.Status = consts.StreamStatusFailed
				resp.StatusMessage = fmt.Sprintf("failed to save vuln db.%v", err)
				_ = os.RemoveAll(aviraDBPathInfo.UpdatePath)
			} else {
				resp.Status = consts.StreamStatusOK
				resp.StatusMessage = consts.StreamMsgSaveAviraOK
			}
			err = s.SendResponse(reqID, resp)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Str("reqID", reqID).Msg("failed to send response")
			} else {
				logging.Get().Info().Str("module", "imagescan").Str("reqID", reqID).Msg("send response ok")
			}
		}()

		if err := vi.UpdateDBService.UpdateDB(context.Background(), imagesecModel.UpdateDbParam{
			DbType: consts.AviraName,
			Data:   payload,
		}); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Str("reqID", reqID).Str("DbType", consts.AviraName).Msg("sub scanner receive db")
		} else {
			logging.Get().Info().Str("module", "imagescan").Str("reqID", reqID).Str("DbType", consts.AviraName).Msg("sub scanner receive db ok")
			return err
		}
		return nil
	}

	err := saveFunc()
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("reqId", reqID).Msg("failed to save vuln db file")
		return err
	}

	logging.Get().Info().Str("module", "imagescan").Str("reqID", reqID).Str("DbType", consts.AviraName).Msg("sub scanner receive db ok")
	return nil
}
