package stream

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"google.golang.org/protobuf/reflect/protoreflect"

	vulnupdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type GrpcHandler struct {
	DB           *databases.RDBInstance
	ServerStream rpcstream.MessageStream
}

func (g *GrpcHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	req := message.(*pb.ImageSecReq)
	msgType := req.ImageSecReqType
	msgID := req.RequestID
	logging.Get().Info().
		Str("reqID", reqID).
		Str("msgID", msgID).
		Int32("type", int32(msgType)).
		Str("dstClusterKey", req.ClusterKey).
		Msg("rcv image sec grpc msg")

	rspFunc := func() {
		resp := &pb.ImageSecResp{}
		resp.Status = 3 // test
		resp.StatusMessage = "not rcv ok"

		err := s.SendResponse(reqID, resp)
		if err != nil {
			logging.Get().Err(err).Str("msgID", msgID).Str("reqID", reqID).Msg("failed to send response")
		} else {
			logging.Get().Info().Str("msgID", msgID).Str("reqID", reqID).Msg("send response ok")
		}
	}
	switch msgType {
	case pb.ImageSecReqType_RegistryHealthyCheck:
		rspFunc()
	case pb.ImageSecReqType_RegistryImageSync:
		rspFunc()
	case pb.ImageSecReqType_RegistryImageScan:
		rspFunc()
	default:
		logging.Get().Error().Int32("type", int32(msgType)).Msg("not support msg type")
	}
}

func (g *GrpcHandler) OnRead(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("onRead not implement")
}

func (g *GrpcHandler) OnUpdate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Info().Str("reqID", reqID).Msg("recv update msg")
	// rspFunc := func(reqID string, status int32, statusMsg string) {
	// 	resp := &pb.ImageSecResp{
	// 		Status:        status,
	// 		StatusMessage: statusMsg,
	// 	}
	// 	if err := s.SendResponse(reqID, resp); err != nil {
	// 		logging.Get().Err(err).Str("reqID", reqID).Msg("failed to send response")
	// 	} else {
	// 		logging.Get().Info().Str("reqID", reqID).Msg("send response ok")
	// 	}
	// }

	// parse pb msg
	req := message.(*pb.ImageSecReq)
	if req.ImageSecReqType == pb.ImageSecReqType_TiDBUpdate || req.ImageSecReqType == pb.ImageSecReqType_AviraDBUpdate ||
		req.ImageSecReqType == pb.ImageSecReqType_ClamavDBUpdate {
		logging.Get().Logger.Info().Msg("ImageSecReq Vuln will Update")
		vulnReq := UpdateReq{}
		// todo: save tidb file
		vulnReq.ServerStream = g.ServerStream
		vulnReq.UpdateDB(s, reqID, req)
	}

	// rspFunc(reqID, 0, "ok")

}

func (g *GrpcHandler) OnDelete(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("onDelete not implement")
}

type UpdateReq struct {
	ServerStream rpcstream.MessageStream `json:"-"`
	Payload      []byte                  `protobuf:"bytes,6,opt,name=Payload,proto3" json:"Payload,omitempty"`
}

func (vuln *UpdateReq) UpdateDB(s rpcstream.Stream, reqID string, req *pb.ImageSecReq) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer func() {
		if ctx.Err() != nil {
			s.SendResponse(reqID, &pb.ImageSecResp{StatusMessage: ctx.Err().Error()})
		}
		cancel()
	}()
	logging.Get().Info().Msgf("stream 开始处理转发 %v %v", req.ImageSecDstType.String(), req.ImageSecDstPath)
	if req.ImageSecDstType == pb.ImageSecDstType_SubScanner {
		var err error
		upSrv := vulnupdata.GetUpdateVersionSrv()
		s.SendResponse(reqID, &pb.ImageSecResp{StatusMessage: "SubScanner更新漏洞库"})
		data := req.Payload
		if req.ImageSecReqType == pb.ImageSecReqType_TiDBUpdate {
			err = vulnupdata.SaveFile(data, filepath.Join(upSrv.PvcPath, "VulnDB.zip"))
			if err != nil {
				logging.Get().Err(err).Msg("save file error")
				return
			}
			go vuln.UpdateVulnDB(s, req, upSrv)
		}
		if req.ImageSecReqType == pb.ImageSecReqType_ClamavDBUpdate || req.ImageSecReqType == pb.ImageSecReqType_AviraDBUpdate {
			err = vulnupdata.SaveFile(data, filepath.Join(upSrv.PvcPath, "maliciousDB.zip"))
			if err != nil {
				logging.Get().Err(err).Msg("save file error")
				return
			}
			go vuln.UpdateClamavDB(s, req, upSrv)
		}
	}
}

func (vuln *UpdateReq) UpdateClamavDB(s rpcstream.Stream, req *pb.ImageSecReq, upSrv *vulnupdata.UpdateVersionSrv) {
	err := vulnupdata.Unzip(filepath.Join(upSrv.PvcPath, "maliciousDB.zip"), filepath.Join(upSrv.PvcPath, "offline"))
	if err != nil {
		logging.Get().Err(err).Msgf("unzip file error")
		return
	}
	versionPath := ""
	objType := ""
	if req.ImageSecReqType == pb.ImageSecReqType_AviraDBUpdate {
		versionPath = scannermodel.AviraVersionPath
		objType = scannermodel.AviraDB
	} else if req.ImageSecReqType == pb.ImageSecReqType_ClamavDBUpdate {
		versionPath = scannermodel.ClamavVersionPath
		objType = scannermodel.ClamavDB
	}
	newVer, err := scannermodel.ReadMaliciousDBVersion(filepath.Join(upSrv.PvcPath, scannermodel.UnzipPath, versionPath), objType)
	if err != nil {
		logging.Get().Err(err).Msgf("read new version file err:%v", err)
		return
	}
	oldVer, err := scannermodel.ReadMaliciousDBVersion(filepath.Join(upSrv.PvcPath, versionPath), objType)
	if err != nil {
		logging.Get().Err(err).Msgf("read old version file err:%v", err)
		return
	}
	if objType == scannermodel.ClamavDB {
		if newVer.Clamav.GetVersion() > oldVer.Clamav.GetVersion() {
			_, err := upSrv.UpdateClamAvDB()
			if err != nil {
				logging.Get().Err(err).Msgf("UpdateClamAvDB error")
				return
			}
			oldVer.Clamav.ClamavVersion = newVer.Clamav.ClamavVersion
			oldVer.Clamav.ComPressDBVersion = newVer.Clamav.ComPressDBVersion
		}
	} else if objType == scannermodel.AviraDB {

		_, err := upSrv.UpdateAvriaDB()
		if err != nil {
			logging.Get().Err(err).Msgf("UpdateAviraDB error")
			return
		}
		oldVer.Avira.AvriaVersion = newVer.Avira.AvriaVersion
		oldVer.Avira.ComPressDBVersion = newVer.Avira.ComPressDBVersion
	}
	writer, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("get writer error")
		return
	}
	sqlData := scannermodel.ScanDBVersion{}
	sqlData.KeyPath = req.ImageSecDstPath
	sqlData.AviraDBVersion = oldVer.Avira
	sqlData.ClamavDBVersion = oldVer.Clamav
	sqlData.ObjectType = scannermodel.SubScannerObject
	sqlByte, err := json.Marshal(sqlData)
	if err != nil {
		logging.Get().Err(err).Msg("Marshal sqlData error")
		return
	}
	if err := scannermodel.SubScannerSendToKafka(writer, scannermodel.SubScannerToMainSql{DalName: "version", Data: sqlByte,
		Action: scannermodel.SubSqlUpdate, Params: objType}); err != nil {
		logging.Get().Err(err).Msg("SubScannerSendToKafka")
	}
}

func (vuln *UpdateReq) UpdateVulnDB(s rpcstream.Stream, req *pb.ImageSecReq, upSrv *vulnupdata.UpdateVersionSrv) {
	err := vulnupdata.Unzip(filepath.Join(upSrv.PvcPath, "VulnDB.zip"), filepath.Join(upSrv.PvcPath, "offline"))
	if err != nil {
		logging.Get().Err(err).Msgf("unzip file error")
		return
	}
	newVer, err := scannermodel.ReadVulnDBVersion(filepath.Join(upSrv.PvcPath, "offline/", scannermodel.VulnVersionPath))
	if err != nil {
		logging.Get().Err(err).Msgf("read new version file err:%v", err)
		return
	}
	oldVer, err := scannermodel.ReadVulnDBVersion(filepath.Join(upSrv.PvcPath, scannermodel.VulnVersionPath))
	if err != nil {
		logging.Get().Err(err).Msgf("read old version file err:%v", err)
		return
	}
	if newVer.GetVersion(scannermodel.TrivyDB) > oldVer.GetVersion(scannermodel.TrivyDB) {
		ok, err := upSrv.UpdateVulnDB()
		if err != nil {
			logging.Get().Err(err).Msgf("updateVulnDB error")
		}
		if ok {
			oldVer.TrivyVersion = newVer.TrivyVersion
			oldVer.ComPressDBVersion = newVer.ComPressDBVersion
		}
	}
	if newVer.GetVersion(scannermodel.CustomDB) > oldVer.GetVersion(scannermodel.CustomDB) {
		ok, err := upSrv.UpdateBoltDB()
		if err != nil {
			logging.Get().Err(err).Msgf("updateBoltDB error")
		}
		if ok {
			oldVer.CustomDBVersion = newVer.CustomDBVersion
		}
	}
	writer, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("get writer error")
		return
	}
	sqlData := scannermodel.ScanDBVersion{}
	sqlData.KeyPath = req.ImageSecDstPath
	sqlData.VulnDBVersion = oldVer
	sqlData.ObjectType = scannermodel.SubScannerObject
	sqlByte, err := json.Marshal(sqlData)
	if err != nil {
		logging.Get().Err(err).Msg("Marshal sqlData error")
		return
	}
	scannermodel.SubScannerSendToKafka(writer, scannermodel.SubScannerToMainSql{DalName: "version", Data: sqlByte, Action: scannermodel.SubSqlUpdate})
}
