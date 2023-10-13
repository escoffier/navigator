package stream

import (
	"fmt"
	"os"

	json "github.com/json-iterator/go"

	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Handler struct {
	taskQueue       *util.Queue
	broadcastServer *util.BroadcastServer
}

func (vi *Handler) OnCreate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
	req, ok := msg.(*pb.ImageSecReq)
	if !ok {
		logging.Get().Info().Msg("ProtoMessage is *pb.ImageSecResp, not *pb.ImageSecReq")
		return
	}

	msgType := req.ImageSecReqType
	msgID := req.MsgID
	logging.Get().Info().Str("msgID", msgID).Int32("type", int32(msgType)).Msg("receive grpc msg")

	switch msgType {
	case pb.ImageSecReqType_NodeImageScan:
		_ = vi.doScanTask(s, reqID, msgID, req.Payload)
	case pb.ImageSecReqType_TiDBUpdate:
		logging.Get().Info().Int32("msgType", int32(msgType)).Msg("get ImageSecReqType_TiDBUpdate")
	case pb.ImageSecReqType_SyncResult:
		logging.Get().Info().Int32("msgType", int32(msgType)).Msg("get ImageSecReqType_SyncResult")
	case pb.ImageSecReqType_SyncConfig:
		// _ = vi.updateConfig(s, reqID, req.Payload)
	case pb.ImageSecReqType_AviraDBUpdate:
		_ = vi.saveAviraDB(s, reqID, req.Payload)
	default:
		logging.Get().Error().Int32("type", int32(msgType)).Msg("not support msg type")
	}
}

func (vi *Handler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-read not implement")
}

func (vi *Handler) OnUpdate(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-update not implement")
}

func (vi *Handler) OnDelete(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-delete not implement")
}

func (vi *Handler) doScanTask(s rpcstream.Stream, reqID, msgID string, payload []byte) error {
	subTask := imagesec.ScanSubTask{}
	err := json.Unmarshal(payload, &subTask)
	if err != nil {
		logging.Get().Err(err).Msg("failed to unmarshal payload to scan task")
		return err
	}
	logging.Get().Info().
		Str("msgID", msgID).
		Str("reqID", reqID).
		Int64("taskID", subTask.TaskID).
		Int64("subTaskID", subTask.SubTaskID).
		Msg("recv scan task")

	vi.taskQueue.Add(subTask)

	logging.Get().Info().
		Str("msgID", msgID).
		Str("reqID", reqID).
		Int64("taskID", subTask.TaskID).
		Int64("subTaskID", subTask.SubTaskID).
		Msg("enqueue subtask ok")

	resp := &pb.ImageSecResp{}
	resp.Status = 0
	resp.StatusMessage = "create subtasks ok"

	err = s.SendResponse(reqID, resp)
	if err != nil {
		logging.Get().Err(err).Str("msgID", msgID).Str("reqID", reqID).Msg("failed to send response")
	} else {
		logging.Get().Info().Str("msgID", msgID).Str("reqID", reqID).Msg("send response ok")
	}

	return nil
}

func (vi *Handler) updateConfig(s rpcstream.Stream, reqID string, payload []byte) error {
	toUpdateConfig := imagesecModel.ImageScanConfig{}
	err := json.Unmarshal(payload, &toUpdateConfig)
	if err != nil {
		logging.Get().Err(err).Msg("failed to unmarshal payload to scan config")
		return err
	}

	// update node image config
	config.UpdateNodeImageConfig(&toUpdateConfig)

	logging.Get().Info().Interface("config", toUpdateConfig).Msg("update node image config end")

	// add msg to broadcast server
	err = vi.broadcastServer.AddMsg(types.NotifyEvent{
		Type:            consts.NotifyEventTypeConfigModified,
		NodeImageConfig: toUpdateConfig,
	})
	if err != nil {
		// just log,still send receive ok response
		logging.Get().Err(err).Msg("failed to add broadcast server")
	}

	resp := &pb.ImageSecResp{}
	resp.Status = 0
	resp.StatusMessage = "config hot update ok"
	err = s.SendResponse(reqID, resp)
	if err != nil {
		logging.Get().Err(err).Str("reqID", reqID).Msg("failed to send response")
	} else {
		logging.Get().Info().Str("reqID", reqID).Msg("send response ok")
	}

	return nil
}

func (vi *Handler) saveAviraDB(s rpcstream.Stream, reqID string, payload []byte) error {

	aviraDBPathInfo := helper.GetAviraDBPathInfo()

	// aviraPath: /host/var/lib/tensor/db/avira/
	// aviraPath := helper.GetDownloadAviraDBPath()
	// aviraName: /host/var/lib/tensor/db/avira/avira.zip
	// aviraName := filepath.Join(aviraPath, consts.AviraDBFile)
	logging.Get().Debug().Str("path", aviraDBPathInfo.UpdatePath).Msg("start save avira db")

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
				logging.Get().Err(err).Str("reqID", reqID).Msg("failed to send response")
			} else {
				logging.Get().Info().Str("reqID", reqID).Msg("send response ok")
			}
		}()

		err = util.MkdirIfNotExist(aviraDBPathInfo.UpdatePath, false)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to mk dir")
			return err
		}

		err = os.WriteFile(aviraDBPathInfo.UpdateZipFile, payload, os.ModePerm)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to write file")
			return err
		}

		err = util.Unzip(aviraDBPathInfo.UpdateZipFile, aviraDBPathInfo.UpdateUnZipPath, consts.VulnDBZipFilePasswd)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to unzip")
			return err
		}

		// check md5
		data, err := os.ReadFile(aviraDBPathInfo.UpdateVersionFile)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to read version file")
			return err
		}
		dbVersion := &types.AviraVersion{}
		err = json.Unmarshal(data, dbVersion)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to unmarshal version")
			return err
		}
		dbFileMD5, err := util.Md5FromFile(aviraDBPathInfo.UpdateZipFile)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to calculate md5")
			return err
		}
		if dbFileMD5 != dbVersion.AviraVersion.Hash {
			err = fmt.Errorf("dbfile version not match.actual md5:%v,md5 in version file:%v", dbFileMD5, dbVersion.AviraVersion.Hash)
			logging.Get().Err(err).Str("reqID", reqID).Msg("md5 not match")
			return err
		}

		// copy version file to notify updater
		// _, err = util.CopyFile(filepath.Join(aviraPath, consts.VersionStr),
		// 	filepath.Join(aviraPath, consts.VulnDBNotifyFilename))

		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to update notify file")
			return err
		}
		return nil
	}

	// save and send response
	err := saveFunc()
	if err != nil {
		logging.Get().Err(err).Str("reqId", reqID).Msg("failed to save vuln db file")
		return err
	}

	logging.Get().Info().Str("reqId", reqID).Msg("save vuln db ok")
	// add msg to broadcast server
	err = vi.broadcastServer.AddMsg(types.NotifyEvent{Type: consts.NotifyEventTypeAviraDBUpdate})
	if err != nil {
		logging.Get().Err(err).Msg("failed to add avira db update msg to broadcast server")
	}

	return nil
}
