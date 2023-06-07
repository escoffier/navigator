package stream

import (
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	imagesec2 "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
	"os"
	"path/filepath"
)

const (
	VulnDBFile = "vuln-db.zip"
)

type Handler struct {
	taskQueue       *util.Queue
	broadcastServer *util.BroadcastServer
}

func (i *Handler) OnCreate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
	req := msg.(*pb.ImageSecReq)
	msgType := req.ImageSecReqType
	msgID := req.RequestID
	logging.Get().Info().Str("msgID", msgID).Int32("type", int32(msgType)).Msg("recv grpc msg")

	switch msgType {
	case pb.ImageSecReqType_NodeImageScan:
		_ = i.doScanTask(s, reqID, msgID, req.Payload)
	case pb.ImageSecReqType_TiDBUpdate:
		_ = i.saveVulnDB(s, reqID, req.Payload)
	case pb.ImageSecReqType_SyncResult:
	case pb.ImageSecReqType_SyncConfig:
		_ = i.updateConfig(s, reqID, req.Payload)
	default:
		logging.Get().Error().Int32("type", int32(msgType)).Msg("not support msg type")
	}
}

func (i *Handler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-read not implement")
}

func (i *Handler) OnUpdate(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-update not implement")
}

func (i *Handler) OnDelete(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("on-delete not implement")
}

func (i *Handler) doScanTask(s rpcstream.Stream, reqID, msgID string, payload []byte) error {
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

	i.taskQueue.Add(subTask)
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

func (i *Handler) updateConfig(s rpcstream.Stream, reqID string, payload []byte) error {
	toUpdateConfig := imagesec2.NodeImageConfig{}
	err := json.Unmarshal(payload, &toUpdateConfig)
	if err != nil {
		logging.Get().Err(err).Msg("failed to unmarshal payload to scan config")
		return err
	}

	// update node image config
	config.UpdateNodeImageConfig(&toUpdateConfig)

	// flush to local file
	if err := config.FlushNodeImageConfigToFile(); err != nil {
		logging.Get().Err(err).Msg("failed to flush node image to local file")
	}

	logging.Get().Info().Interface("config", toUpdateConfig).Msg("update node image config end")

	// add msg to broadcast server
	err = i.broadcastServer.AddMsg(types.NotifyEvent{
		Type:            types.NotifyEventTypeConfigModified,
		NodeImageConfig: toUpdateConfig,
	})
	if err != nil {
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
func (i *Handler) saveVulnDB(s rpcstream.Stream, reqID string, payload []byte) error {
	// save vuln db to path: /host/var/lib/tensor/db/vuln/
	tmpVulnDBPath := helper.GetDownloadVulnDBPath()
	tmpVulnDBFile := filepath.Join(tmpVulnDBPath, VulnDBFile)
	logging.Get().Debug().Str("path", tmpVulnDBPath).Msg("start save vuln db")

	saveFunc := func() error {
		var err error
		defer func() {
			resp := &pb.ImageSecResp{}
			if err != nil {
				resp.Status = 1
				resp.StatusMessage = fmt.Sprintf("failed to save vuln db.%v", err)
				_ = os.RemoveAll(tmpVulnDBPath)
			} else {
				resp.Status = 0
				resp.StatusMessage = "save vuln db ok"
			}
			err = s.SendResponse(reqID, resp)
			if err != nil {
				logging.Get().Err(err).Str("reqID", reqID).Msg("failed to send response")
			} else {
				logging.Get().Info().Str("reqID", reqID).Msg("send response ok")
			}
		}()

		err = util.MkdirIfNotExist(tmpVulnDBPath, false)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to mk dir")
			return err
		}

		err = os.WriteFile(tmpVulnDBFile, payload, os.ModePerm)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to write file")
			return err
		}

		// unzip. dir tree:
		// --trivy/trivy.db
		// --trivy/version
		// --version
		err = util.Unzip(tmpVulnDBFile, tmpVulnDBPath, helper.VulnDBZipFilePasswd)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to unzip")
			return err
		}

		// check md5
		data, err := os.ReadFile(helper.GetDownloadVulnDBVersionPath(tmpVulnDBPath))
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to read version file")
			return err
		}
		dbVersion := &imagesec.OfflineVulnDBVersion{}
		err = json.Unmarshal(data, dbVersion)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to unmarshal version")
			return err
		}
		dbFileMD5, err := util.Md5FromFile(helper.GetDownloadVulnDBFilePath(tmpVulnDBPath))
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Msg("failed to calculate md5")
			return err
		}
		if dbFileMD5 != dbVersion.TrivyVersion.Hash {
			err = fmt.Errorf("dbfile version not match.actual md5:%v,md5 in version file:%v", dbFileMD5, dbVersion.TrivyVersion.Hash)
			logging.Get().Err(err).Str("reqID", reqID).Msg("md5 not match")
			return err
		}

		// copy version file to notify updater
		_, err = util.CopyFile(filepath.Join(tmpVulnDBPath, helper.VulnDBVersionFileName), filepath.Join(tmpVulnDBPath, helper.VulnDBNotifyFileName))
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
	err = i.broadcastServer.AddMsg(types.NotifyEvent{Type: types.NotifyEventTypeVulnDBUpdate})
	if err != nil {
		logging.Get().Err(err).Msg("failed to add vuln db update msg to broadcast server")
	}

	return nil
}
