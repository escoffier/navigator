package imagesecStream

import (
	"context"
	"encoding/json"

	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type Handler struct {
	ScanSubtaskReceiver ScanSubtaskReceiver
	ImageSyncer         ImageSyncer
	RegistryValidator   RegistryValidator
	ImageSecRespChan    chan RpcPong
	Log                 *scannerUtils.LogEvent
}

func NewHandler(receiver ScanSubtaskReceiver, syncer ImageSyncer, registryValidator RegistryValidator) *Handler {
	s := &Handler{
		ScanSubtaskReceiver: receiver,
		ImageSyncer:         syncer,
		RegistryValidator:   registryValidator,
		ImageSecRespChan:    make(chan RpcPong),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("Handler"),
			scannerUtils.WithModule(consts.ModuleRpcStream),
		),
	}
	s.SendResponse(context.Background())
	return s
}

func (vi *Handler) OnCreate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
	req := msg.(*pb.ImageSecReq)
	msgType := req.ImageSecReqType
	msgID := req.MsgID

	vi.Log.Info().Str("regID", reqID).Str("msgID", msgID).Str("type", GetRpcType(req.ImageSecReqType)).
		Msg("receive grpc msg")

	switch msgType {
	case pb.ImageSecReqType_RegistryImageScan:
		_ = vi.addScanTask(s, reqID, msgID, req.Payload)
	case pb.ImageSecReqType_RegistryImageSync:
		_ = vi.addSyncTask(s, reqID, msgID, req.Payload)
	case pb.ImageSecReqType_RegistryHealthyCheck:
		_ = vi.checkReg(s, reqID, msgID, req.Payload)
	default:
		vi.Log.Error().Int32("type", int32(msgType)).Msg("not support msg type")
	}
}

func (vi *Handler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	vi.Log.Error().Msg("on-read not implement")
}

func (vi *Handler) OnUpdate(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	vi.Log.Error().Msg("on-update not implement")
}

func (vi *Handler) OnDelete(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	vi.Log.Info().Msg("rcp stream delete")
}

// 扫描任务
func (vi *Handler) addScanTask(s rpcstream.Stream, reqID, msgID string, payload []byte) error {
	subTask := imagesecTypes.ScanSubTask{}
	err := json.Unmarshal(payload, &subTask)

	pong := RpcPong{Stream: s, RegID: reqID}

	if err != nil {
		pong.ImageSecResp = &pb.ImageSecResp{BizCode: consts.StreamStatusFailed, BizMessage: err.Error()}

		go func() { vi.ImageSecRespChan <- pong }()

		vi.Log.Err(err).Msg("failed to unmarshal payload to scan task")
		return err
	}

	_ = vi.ScanSubtaskReceiver.ReceiveScanSubtask(context.Background(), subTask)

	pong.ImageSecResp = &pb.ImageSecResp{BizCode: consts.StreamStatusStartScanTask}

	go func() { vi.ImageSecRespChan <- pong }()

	vi.Log.Info().
		Str("msgID", msgID).
		Str("reqID", reqID).
		Int64("taskID", subTask.TaskID).
		Int64("subTaskID", subTask.SubTaskID).
		Interface("RegInfo", subTask.RegInfo).
		Interface("ImageMeta", subTask.RegImageMeta).
		Interface("ScanInstance", subTask.ScanInstance).
		Interface("SensitiveRules", subTask.SensitiveRules).
		Msg("receive registry scan task")

	return nil
}

// 同步任务
func (vi *Handler) addSyncTask(s rpcstream.Stream, reqID, msgID string, payload []byte) error {
	subTask := imagesecModel.ImageSyncTask{}
	err := json.Unmarshal(payload, &subTask)
	pong := RpcPong{Stream: s, RegID: reqID}

	if err != nil {
		pong.ImageSecResp = &pb.ImageSecResp{BizCode: consts.StreamStatusRegNotOK, BizMessage: err.Error()}
		go func() { vi.ImageSecRespChan <- pong }()

		vi.Log.Err(err).Msg("addSyncTask failed to unmarshal payload to scan task")
		return err
	}
	if subTask.SyncType != imagesecModel.CycleIncSync.String() {
		vi.Log.Info().
			Str("msgID", msgID).
			Str("reqID", reqID).
			Int64("registryID", subTask.RegistryID).
			Interface("regName", subTask.Registry.Name).
			Interface("regUrl", subTask.Registry.Url).
			Interface("regUsername", subTask.Registry.Username).
			Interface("ScanInsInfo", subTask.ScanInsInfo).
			Msg("receive rpc addSyncTask sync task")
	}

	status := vi.ImageSyncer.SyncImage(context.Background(), subTask)
	switch status {
	case imagesecModel.TaskStatusImageSyncFinishedStr:
		pong.ImageSecResp = &pb.ImageSecResp{BizMessage: status, BizCode: consts.StreamStatusSyncFinished}
	case imagesecModel.TaskStatusInprogressStr:
		pong.ImageSecResp = &pb.ImageSecResp{BizMessage: status, BizCode: consts.StreamStatusSyncProgress}
	default:
		pong.ImageSecResp = &pb.ImageSecResp{BizMessage: status, BizCode: consts.StreamStatusSyncFailed}
	}

	go func() { vi.ImageSecRespChan <- pong }()

	return nil
}

// 回包
func (vi *Handler) SendResponse(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				vi.Log.Error().Msg("SenResponse recover panic")
			}
		}()

		for res := range vi.ImageSecRespChan {
			if err := res.Stream.SendResponse(res.RegID, res.ImageSecResp); err != nil {
				vi.Log.Err(err).Msg("SendResponse")
			}
		}
	}()
}

func (vi *Handler) checkReg(s rpcstream.Stream, reqID, msgID string, payload []byte) error {

	reg := imagesecModel.Registry{}
	err := json.Unmarshal(payload, &reg)

	pong := RpcPong{Stream: s, RegID: reqID}

	if err != nil {
		pong.ImageSecResp = &pb.ImageSecResp{BizCode: consts.StreamStatusRegNotOK, BizMessage: err.Error()}

		go func() { vi.ImageSecRespChan <- pong }()

		vi.Log.Err(err).Str("payload", string(payload)).Msg("ValidateRegistry failed to unmarshal payload to reg")
		return err
	}
	vi.Log.Info().
		Str("msgID", msgID).
		Str("reqID", reqID).
		Int64("registryID", reg.ID).
		Str("regName", reg.Name).
		Str("regUrl", reg.Url).
		Str("regUser", reg.Username).
		Msg("receive rpc checkReg task")

	err = vi.RegistryValidator.ValidateRegistry(context.Background(), reg)

	if err != nil {
		pong.ImageSecResp = &pb.ImageSecResp{BizCode: consts.StreamStatusRegNotOK, BizMessage: err.Error()}
		go func() { vi.ImageSecRespChan <- pong }()
		vi.Log.Err(err).Interface("reg", reg).Msg("ValidateRegistry fail")
		return err
	}

	pong.ImageSecResp = &pb.ImageSecResp{BizCode: consts.StreamStatusRegOK, BizMessage: imagesecModel.RegNormal}

	go func() { vi.ImageSecRespChan <- pong }()

	vi.Log.Info().Interface("reg", reg).Str("regType", reg.RegType).Msg("ValidateRegistry succeed")
	return nil
}
