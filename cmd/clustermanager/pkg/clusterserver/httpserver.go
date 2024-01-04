package clusterserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	model1 "gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/sdk/palace"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	json "github.com/json-iterator/go"
	param "github.com/oceanicdev/chi-param"

	clusterAgent "gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/attack"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/security-rd/go-pkg/logging"
	pkg "gitlab.com/security-rd/go-pkg/model"
)

type ClusterServer struct {
	Palace             *palace.Palace
	server             *http.Server
	engine             *gin.Engine
	ClusterID          string
	Name               string
	TLSServer          bool
	config             *config.Config
	clusterManager     *k8s.ClusterManager
	attackCacheService *attack.CacheService
	agent              *clusterAgent.ClusterAgent
}

func (cs *ClusterServer) SetClusterManager(cm *k8s.ClusterManager) {
	cs.clusterManager = cm
}
func (cs *ClusterServer) handleClusterQuery(c *gin.Context) {
	clusterInfo := &TensorCluster{
		Key:           cs.ClusterID,
		Name:          cs.config.Name,
		ConsoleURL:    getConsoleURLPrefix(cs.config.MasterAddr),
		Description:   "",
		Status:        0,
		K8SRestConfig: cs.agent.KubeRestConfig,
	}
	c.JSON(http.StatusOK, clusterInfo)
}

func (cs *ClusterServer) handleWatchCluster(c *gin.Context) {
	if cs.clusterManager == nil {
		c.String(http.StatusInternalServerError, "fail to watch: this not the host cluster")
		return
	}

	var tensorCluster model.TensorCluster

	err := c.ShouldBindJSON(&tensorCluster)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	err = cs.clusterManager.UpdateCluster(ctx, &tensorCluster)
	if err != nil {
		logging.Get().Err(err).Msg("watch cluster err.")

		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, "OK")
}

func (cs *ClusterServer) handleATTACKLatestData(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c, time.Second*2)
	defer cancel()

	reqVersion, err := param.QueryInt64(c.Request, "curVersion")
	if err != nil {
		logging.Get().Err(err).Int64("reqVersion", reqVersion).Msg("parse curVersion err")
		c.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: err.Error(),
			},
		})
		return
	}

	reqDataVersion, err := param.QueryInt64(c.Request, "curDataVersion")
	if err != nil {
		reqDataVersion = 0
	}
	reqSettingVersion, err := param.QueryInt64(c.Request, "curSettingVersion")
	if err != nil {
		reqSettingVersion = 0
	}

	logging.Get().Debug().Int64("curVersion", reqVersion).Int64("curDataVersion", reqDataVersion).Int64("curSettingVersion", reqSettingVersion).Msg("request param")
	data, err := cs.attackCacheService.GetLatestData(ctx, reqVersion, reqDataVersion, reqSettingVersion)
	if err != nil {
		logging.Get().Err(err).Int64("reqDataVersion", reqDataVersion).Int64("reqSettingVersion", reqSettingVersion).Msg("get latest data err")
		c.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: err.Error(),
			},
		})
		return
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logging.Get().Err(err).Int64("reqDataVersion", reqDataVersion).Int64("reqSettingVersion", reqSettingVersion).Msg("marshal err")
		c.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, response.HTTPEnvelope{
		Data: &response.HTTPData{
			Item: dataBytes,
		},
	})
}

func (cs *ClusterServer) handleAttackLogs(c *gin.Context) {

	var waf model.WafAttackLogs
	err := c.BindJSON(&waf)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: err.Error(),
			},
		})
		return
	}

	logging.Get().Info().Msgf("rcv waf log : %+v", waf)
	var attack pkg.WafDetectionMessage
	attack.CreatedAt = time.Now().UnixMilli()
	attack.AppName = waf.AppName
	attack.ClusterKey = waf.ClusterKey
	attack.Namespace = waf.Namespace
	attack.ResKind = waf.ResKind
	attack.ResName = waf.ResName
	attack.ServiceID = waf.ServiceId
	for i := 0; i < len(waf.AttackedLog); i++ {
		atLog := pkg.WafDetectionAttackedLog{
			RuleID:         waf.AttackedLog[i].RuleId,
			Action:         waf.AttackedLog[i].Action,
			RuleName:       waf.AttackedLog[i].RuleName,
			AttackIP:       waf.AttackedLog[i].AttackIp,
			AttackType:     waf.AttackedLog[i].AttackType,
			AttackedApp:    waf.AttackedLog[i].AttackedApp,
			AttackedURL:    waf.AttackedLog[i].AttackedUrl,
			AttackLoad:     waf.AttackedLog[i].AttackLoad,
			AttackTime:     waf.AttackedLog[i].AttackTime,
			RspContentType: waf.AttackedLog[i].RspContentType,
			ReqPkg:         waf.AttackedLog[i].ReqPkg,
			RspPkg:         waf.AttackedLog[i].RspPkg,
		}
		attack.AttackedLog = append(attack.AttackedLog, atLog)
	}

	err = cs.Palace.SendWafDetection(attack)
	if err != nil {
		logging.Get().Error().Msgf("save waf attack log failed, error : %+v", err)
	}

	c.JSON(http.StatusOK, response.HTTPEnvelope{
		Data: &response.HTTPData{
			Status: 0,
		},
	})
}

func (cs *ClusterServer) handleMicrosegEvents(c *gin.Context) {
	var microsegEvent model1.TensorMicrosegEvent
	err := c.ShouldBindJSON(&microsegEvent)
	if err != nil {
		c.String(http.StatusInternalServerError, "unmarshal microseg event err: %v", err)
		return
	}
	logging.Get().Info().Msgf("microseg event: %+v", microsegEvent)
	err = cs.Palace.SendMicrosegEvent(microsegEvent)
	if err != nil {
		c.String(http.StatusInternalServerError, "send microseg event err: %v", err)
		return
	}
	c.String(http.StatusOK, "ok")
}

func NewHTTPServer(agent *clusterAgent.ClusterAgent, config *config.Config, Palace *palace.Palace) (*ClusterServer, error) {
	tlsConfig := &tls.Config{}
	if config.TLSServer {
		tlsKeyPair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			logging.Get().Err(err).Msg("failed to load tls key from file")
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{tlsKeyPair}
	}

	s := &ClusterServer{
		Palace:             Palace,
		ClusterID:          agent.CusterID,
		Name:               config.Name,
		config:             config,
		attackCacheService: attack.NewCacheService(config.MasterAddr, agent),
		agent:              agent,
	}

	r := gin.Default()
	if config.Profile {
		pprof.Register(r)
	}
	r.GET("/internal/cluster", s.handleClusterQuery)
	r.GET("/internal/watch_cluster", s.handleWatchCluster)
	r.GET("/api/openapi/ATTCK/latestData", s.handleATTACKLatestData)
	r.POST("/internal/attack/logs", s.handleAttackLogs)
	r.POST("/internal/microseg/event", s.handleMicrosegEvents)

	s.engine = r

	return s, nil
}

func (cs *ClusterServer) Run() {
	var err error
	if cs.TLSServer {
		err = cs.engine.RunTLS(fmt.Sprintf(":%d", cs.config.Port), cs.config.CertFile, cs.config.KeyFile)
	} else {
		err = cs.engine.Run(fmt.Sprintf(":%d", cs.config.Port))
	}

	if err != nil {
		logging.Get().Err(err).Msg("listen tcp address failed")
		return
	}
}

func getConsoleURLPrefix(masterAddr string) string {
	if strings.Contains(masterAddr, "http") {
		return masterAddr
	}
	return "http://" + masterAddr
}
