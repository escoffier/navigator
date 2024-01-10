package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/waf.security.io/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	// "k8s.io/apimachinery/pkg/util/yaml"
)

// var rule []*Rule = []*Rule{
// 	{
// 		ID:          311003,
// 		Level:       3,
// 		Name:        "RFI-BASE-Usual1",
// 		Description: "远程文件包含检测1",
// 		Expr:        "(file|ftp?|ftps?|https?)://([^/]*).*",
// 		Mode:        " match(urlDecode(args),full)",
// 	},
// }

const (
	AcceptLanguage   = "Accept-Language"
	wafConfig        = "waf-rules"
	blackWhiteConfig = "waf-blackwhitelists"
)

var (
	instance *WafService
	rlOnce   sync.Once
)

type WafService struct {
	sherlockClient *echelper.SherlockClient
	rdb            *databases.RDBInstance
	stream         rpcstream.MessageStream
	cfg            *WafOption
	rootNamespace  string
}

type Workload struct {
	ClusterKey string `json:"cluster_key"`
	Namespace  string `json:"namespace"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
}

type WafRequest struct {
	ID           uint32   `json:"id"`
	Name         string   `json:"name"`
	ClusterKey   string   `json:"cluster_key"`
	Namespace    string   `json:"namespace"`
	Kind         string   `json:"kind"`
	ResourceName string   `json:"resource_name"`
	Hosts        []string `json:"hosts"`
	Host         string   `json:"host"`
	UriPrefix    string   `json:"uri_prefix"`
	Mode         string   `json:"mode"`
	TLSCrt       string   `json:"tls_crt"`
	TLSKey       string   `json:"tls_key"`
	Description  string   `json:"description"`
	Protocol     string   `json:"protocol"`
}

type SecretRequest struct {
	ClusterKey string
	Namespace  string
	Kind       string
	Name       string
	CertData   []byte
	KeyData    []byte
}

type RuleRequest struct {
	CategoryID []string `json:"category_id"`
	Status     int      `json:"status"`
}

type MatcherExpr struct {
	ID        uint32   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Scope     []uint32 `json:"scope,omitempty"`
	ScopeName []string `json:"scope_name,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	Expr      string   `json:"expr,omitempty"`
	Global    bool     `json:"global"`
	Status    int32    `json:"status"`
}

func InitWafService(rdb *databases.RDBInstance, sherlockClient *echelper.SherlockClient, rootNamespace string) error {
	var err error
	rlOnce.Do(func() {
		instance, err = NewWafService(rdb, sherlockClient, rootNamespace)
	})
	return err
}

func GetService(_ context.Context) (*WafService, bool) {
	return instance, instance != nil
}

func NewWafService(rdb *databases.RDBInstance, sherlockClient *echelper.SherlockClient, rootNamespace string) (*WafService, error) {
	return &WafService{
		sherlockClient: sherlockClient,
		rdb:            rdb,
		cfg: &WafOption{
			WasmUrl: "oci://harbor.tensorsecurity.com/library/waf_wasm:latest",
		},
		rootNamespace: rootNamespace,
	}, nil
}

func GenID(strs ...string) uint32 {
	s := strings.Join(strs, ",")
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

func (s *WafService) AddWafService(ctx context.Context, req *WafRequest) (uint32, error) {
	var id uint32
	var err error
	tErr := s.rdb.Get().Transaction(func(tx *gorm.DB) error {
		var secretName string
		if req.TLSCrt != "" && req.TLSKey != "" {
			crtData, keyData, err := dal.GetCerts(ctx, s.rdb.Get(), req.TLSCrt, req.TLSKey)
			if err != nil {
				return err
			}
			secretName = req.ResourceName + "-termination"
			s.CreateTLSSecret(ctx, &SecretRequest{
				ClusterKey: req.ClusterKey,
				Namespace:  req.Namespace,
				Name:       secretName,
				CertData:   crtData,
				KeyData:    keyData,
			})
		}

		id, err = dal.CreateWafService(ctx, tx, &model.WafService{
			Name:         req.Name,
			ClusterKey:   req.ClusterKey,
			Namespace:    req.Namespace,
			Kind:         req.Kind,
			ResourceName: req.ResourceName,
			UriPrefix:    req.UriPrefix,
			Mode:         req.Mode,
			Host:         req.Host,
			Description:  req.Description,
			Protocol:     req.Protocol,
		})
		if err != nil {
			return err
		}
		wafService := &v1alpha1.Service{
			ObjectMeta: v1.ObjectMeta{
				Namespace: req.Namespace,
				Name:      req.ResourceName,
			},
			Spec: v1alpha1.ServiceSpec{
				HostNames: []string{req.Host},
				Mode:      req.Mode,
				Workload: v1alpha1.WorkloadRef{
					ClusterKey: req.ClusterKey,
					Namespace:  req.Namespace,
					Kind:       req.Kind,
					Name:       req.ResourceName,
				},
				Secret: secretName,
				Uri: &v1alpha1.StringMatch{
					Prefix: req.UriPrefix,
				},
				ServiceName: req.Name,
				ServiceID:   id,
			},
		}
		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			return fmt.Errorf("cluster manager not available")
		}
		clientset, ok := clusterManager.GetClient(req.ClusterKey)
		if !ok {
			return fmt.Errorf("clientset of cluster: %s not available", req.ClusterKey)
		}

		_, err = clientset.TensorClientset.WafV1alpha1().Services(req.Namespace).Create(ctx, wafService, v1.CreateOptions{})
		return err
	})

	return id, tErr
	// return s.AddWafWasmPlugin(ctx, req.ClusterKey, req.Namespace, req.Name, matchLabel, wasmConfig)
}

func (s *WafService) UpdateWafService(ctx context.Context, req *WafRequest) error {
	mWaf, err := dal.GetWafService(ctx, s.rdb.Get(), req.ID)
	if err != nil {
		return err
	}

	mWaf.Description = req.Description
	mWaf.Mode = req.Mode
	mWaf.UriPrefix = req.UriPrefix
	mWaf.Name = req.Name
	_, err = dal.UpsertWafService(ctx, s.rdb.Get(), mWaf)
	if err != nil {
		return err
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(mWaf.ClusterKey)
	if !ok {
		return fmt.Errorf("clientset of cluster: %s not available", req.ClusterKey)
	}

	logging.Get().Info().Msgf("update waf service : %s", mWaf.Name)

	svc, err := clientset.TensorClientset.WafV1alpha1().Services(mWaf.Namespace).Get(ctx, mWaf.ResourceName, v1.GetOptions{})
	if err != nil {
		return err
	}
	wafService := svc.DeepCopy()
	wafService.Spec.Uri = &v1alpha1.StringMatch{
		Prefix: req.UriPrefix,
	}
	wafService.Spec.Mode = req.Mode

	_, err = clientset.TensorClientset.WafV1alpha1().Services(mWaf.Namespace).Update(ctx, wafService, v1.UpdateOptions{})
	return err
}

func (s *WafService) GetWafServices(ctx context.Context, query *dal.ServiceQueryOption, offset, limit int) ([]*model.WafService, int64, error) {

	services, err := dal.GetWafServices(ctx, s.rdb.Get(), query, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountWafServices(ctx, s.rdb.Get(), query)
	if err != nil {
		return nil, 0, err
	}
	return services, cnt, nil
}

func (s *WafService) GetWafService(ctx context.Context, id uint32) (*model.WafService, error) {
	service, err := dal.GetWafService(ctx, s.rdb.Get(), id)
	if err != nil {
		return nil, err
	}

	return service, nil
}

func (s *WafService) CreateTLSSecret(ctx context.Context, req *SecretRequest) error {
	secret := corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
		Data: map[string][]byte{
			"tls.crt": req.CertData,
			"tls.key": req.KeyData,
		},
		Type: corev1.SecretTypeTLS,
	}
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(req.ClusterKey)
	if !ok {
		return fmt.Errorf("clientset of cluster: %s not available", req.ClusterKey)
	}
	_, err := clientset.Clientset.CoreV1().Secrets(req.Namespace).Create(ctx, &secret, v1.CreateOptions{})
	return err
}

func (s *WafService) DeleteSerivce(ctx context.Context, id uint32) error {
	tErr := s.rdb.Get().Transaction(func(tx *gorm.DB) error {
		svc, err := dal.GetWafService(ctx, tx, id)
		if err != nil {
			return err
		}
		err = dal.DeleteWafService(ctx, tx, id)
		if err != nil {
			return err
		}

		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			return fmt.Errorf("cluster manager not available")
		}
		clientset, ok := clusterManager.GetClient(svc.ClusterKey)
		if !ok {
			return fmt.Errorf("clientset of cluster: %s not available", svc.ClusterKey)
		}

		err = clientset.TensorClientset.WafV1alpha1().Services(svc.Namespace).Delete(ctx, svc.ResourceName, v1.DeleteOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				logging.Get().Info().Msgf("waf service %s/%s has been deleted: ", svc.Namespace, svc.Name)
				return nil
			}
			logging.Get().Err(err).Msgf("delete waf service %s/%s err", svc.Namespace, svc.ResourceName)
			return err
		}
		return nil
	})
	return tErr
}

func (s *WafService) Config(ctx context.Context, config *WafConfig) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}

	headers := sets.NewString(config.DetectHeaders...)
	if !headers.Has("url") {
		config.DetectHeaders = append(config.DetectHeaders, "url")
	}
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	clusterManager.TraverseClient(func(key string, client *assets.Clientset) bool {
		var cm *corev1.ConfigMap
		cm, err = client.CoreV1().ConfigMaps(s.rootNamespace).Get(ctx, wafConfig, v1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				_, err = client.CoreV1().ConfigMaps(s.rootNamespace).Create(ctx, &corev1.ConfigMap{
					ObjectMeta: v1.ObjectMeta{
						Namespace: s.rootNamespace,
						Name:      wafConfig,
					},
					Data: map[string]string{
						"config": string(data),
					},
				}, v1.CreateOptions{})

				return err == nil
			}
			return false
		}

		cm.Data["config"] = string(data)
		_, err = client.CoreV1().ConfigMaps(s.rootNamespace).Update(ctx, cm, v1.UpdateOptions{})
		return err == nil
	})
	return err
}

func (s *WafService) GetConfig(ctx context.Context) (*WafConfig, error) {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, fmt.Errorf("cluster manager not available")
	}
	cm, err := clusterManager.GetHostClient().Clientset.CoreV1().ConfigMaps(s.rootNamespace).Get(ctx, wafConfig, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return &WafConfig{
				ExcludedFileTypes: []string{"url"},
			}, nil
		}
		return nil, err
	}
	if data, ok := cm.Data["config"]; ok {
		config := &WafConfig{}
		err = json.Unmarshal([]byte(data), config)
		if err != nil {
			return nil, err
		}
		for i := range config.DetectHeaders {
			if config.DetectHeaders[i] == "url" {
				config.DetectHeaders = append(config.DetectHeaders[:i], config.DetectHeaders[i+1:]...)
				break
			}
		}
		return config, nil
	}
	return &WafConfig{}, nil
}

func (s *WafService) attachSigleMatchExpression(ctx context.Context, request *MatcherExpr, wafSvc *model.WafService) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(wafSvc.ClusterKey)
	if !ok {
		return fmt.Errorf("clientset of cluster: %s not available", wafSvc.ClusterKey)
	}
	svc, err := clientset.TensorClientset.WafV1alpha1().Services(wafSvc.Namespace).Get(ctx, wafSvc.ResourceName, v1.GetOptions{})
	if err != nil {
		return err
	}
	wafService := svc.DeepCopy()

	found := false
	for i := range wafService.Spec.BlackWhireLists {
		if wafService.Spec.BlackWhireLists[i].ID == request.ID {
			wafService.Spec.BlackWhireLists[i] = v1alpha1.MatchExpression{
				ID:     request.ID,
				Name:   request.Name,
				Mode:   request.Mode,
				Expr:   request.Expr,
				Status: request.Status,
			}
			found = true
			break
		}
	}
	if !found {
		// Make sure black/white lists for specific resources are at the head of the list
		if len(wafService.Spec.BlackWhireLists) == 0 {
			wafService.Spec.BlackWhireLists = append(wafService.Spec.BlackWhireLists, v1alpha1.MatchExpression{
				ID:     request.ID,
				Name:   request.Name,
				Mode:   request.Mode,
				Expr:   request.Expr,
				Status: request.Status,
			})
		} else {
			wafService.Spec.BlackWhireLists = append([]v1alpha1.MatchExpression{
				{
					ID:     request.ID,
					Name:   request.Name,
					Mode:   request.Mode,
					Expr:   request.Expr,
					Status: request.Status,
				},
			}, wafService.Spec.BlackWhireLists...)
		}
	}
	logging.Get().Info().Msgf("update waf service %s/%s", wafService.Namespace, wafService.Name)
	_, err = clientset.TensorClientset.WafV1alpha1().Services(wafSvc.Namespace).Update(ctx, wafService, v1.UpdateOptions{})
	return err
}

func (s *WafService) removeSigleMatchExpression(ctx context.Context, id uint32, wafSvc *model.WafService) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(wafSvc.ClusterKey)
	if !ok {
		return fmt.Errorf("clientset of cluster: %s not available", wafSvc.ClusterKey)
	}
	svc, err := clientset.TensorClientset.WafV1alpha1().Services(wafSvc.Namespace).Get(ctx, wafSvc.ResourceName, v1.GetOptions{})
	if err != nil {
		return err
	}
	wafService := svc.DeepCopy()
	for i := range wafService.Spec.BlackWhireLists {
		if wafService.Spec.BlackWhireLists[i].ID == id {
			wafService.Spec.BlackWhireLists = append(wafService.Spec.BlackWhireLists[:i], wafService.Spec.BlackWhireLists[i+1:]...)
			break
		}
	}
	_, err = clientset.TensorClientset.WafV1alpha1().Services(wafSvc.Namespace).Update(ctx, wafService, v1.UpdateOptions{})
	return err
}

func (s *WafService) attachGlobalMatchExpression(ctx context.Context, request *MatcherExpr) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	var err error
	clusterManager.TraverseClient(func(clusterKey string, client *assets.Clientset) bool {
		var cm *corev1.ConfigMap
		cm, err = client.CoreV1().ConfigMaps(s.rootNamespace).Get(ctx, blackWhiteConfig, v1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				cm = &corev1.ConfigMap{
					ObjectMeta: v1.ObjectMeta{
						Namespace: s.rootNamespace,
						Name:      blackWhiteConfig,
						Labels: map[string]string{
							"app.kubernetes.io/component": "waf-rules",
						},
					},
				}
				cm, err = client.CoreV1().ConfigMaps(s.rootNamespace).Create(ctx, cm, v1.CreateOptions{})
				if err != nil {
					return false
				}
			} else {
				return false
			}
		}
		key := "expr"
		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}

		bwList := []v1alpha1.MatchExpression{}
		if data, exist := cm.Data[key]; exist {
			err = json.Unmarshal([]byte(data), &bwList)
			if err != nil {
				return false
			}

			found := false
			//replace existed expression
			for i, expr := range bwList {
				if expr.ID == request.ID {
					bwList[i] = v1alpha1.MatchExpression{
						ID:     request.ID,
						Name:   request.Name,
						Mode:   request.Mode,
						Expr:   request.Expr,
						Status: request.Status,
					}
					found = true
					break
				}
			}
			if !found {
				bwList = append(bwList, v1alpha1.MatchExpression{
					ID:     request.ID,
					Name:   request.Name,
					Mode:   request.Mode,
					Expr:   request.Expr,
					Status: request.Status,
				})
			}
		} else {
			bwList = []v1alpha1.MatchExpression{
				{
					ID:     request.ID,
					Name:   request.Name,
					Mode:   request.Mode,
					Expr:   request.Expr,
					Status: request.Status,
				},
			}
		}
		var data []byte
		data, err = json.Marshal(bwList)
		if err != nil {
			return false
		}
		logging.Get().Info().Msgf("global expr: %s", string(data))
		cm.Data[key] = string(data)
		_, err = client.CoreV1().ConfigMaps(s.rootNamespace).Update(ctx, cm, v1.UpdateOptions{})
		return err == nil
	})
	return err
}

func (s *WafService) removeGlobalMatchExpression(ctx context.Context, id uint32) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	var err error
	clusterManager.TraverseClient(func(clusterKey string, client *assets.Clientset) bool {
		var cm *corev1.ConfigMap
		cm, err = client.CoreV1().ConfigMaps("tensorsec").Get(ctx, blackWhiteConfig, v1.GetOptions{})
		if err != nil {
			err = fmt.Errorf("get configmap err when removing gloabal expr:  %w", err)
			return false
		}
		key := "expr"
		bwList := []v1alpha1.MatchExpression{}
		if cm.Data != nil {
			if data, exist := cm.Data[key]; exist {
				err = json.Unmarshal([]byte(data), &bwList)
				if err != nil {
					err = fmt.Errorf("unmarshal err when removing gloabal expr: %w", err)
					return false
				}
				for i := range bwList {
					if bwList[i].ID == id {
						bwList = append(bwList[:i], bwList[i+1:]...)
						break
					}
				}
				data, _ := json.Marshal(bwList)
				cm.Data[key] = string(data)
				_, err = client.CoreV1().ConfigMaps("tensorsec").Update(ctx, cm, v1.UpdateOptions{})
				if err != nil {
					err = fmt.Errorf("update cm err when removing gloabal expr: %w", err)
					return false
				}
			}
		}
		return true
	})
	return err
}

func (s *WafService) AddMatchExpression(ctx context.Context, request *MatcherExpr) (uint32, error) {
	var id uint32
	tErr := s.rdb.Get().Transaction(func(tx *gorm.DB) error {
		var err error
		id, err = dal.AddBlackWhiteList(ctx, s.rdb.Get(), &model.MatcherExpr{
			TableBase: model.TableBase{
				ID:     request.ID,
				Status: request.Status,
			},
			Name:   request.Name,
			Scope:  request.Scope,
			Mode:   request.Mode,
			Expr:   request.Expr,
			Global: request.Global,
		})
		if err != nil {
			return err
		}
		request.ID = id
		if !request.Global {
			for _, scope := range request.Scope {
				wafSvc, err := dal.GetWafService(ctx, s.rdb.Get(), uint32(scope))
				if err != nil {
					return err
				}
				err = dal.UpdatetServiceExpr(ctx, s.rdb.Get(), wafSvc.ID, request.ID)
				if err != nil {
					return err
				}
				err = s.attachSigleMatchExpression(ctx, request, wafSvc)
				if err != nil {
					return err
				}
			}
		} else {
			err = s.attachGlobalMatchExpression(ctx, request)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return id, tErr
}

func (s *WafService) UpdateMatchExpression(ctx context.Context, request *MatcherExpr) error {
	tErr := s.rdb.Get().Transaction(func(tx *gorm.DB) error {
		oldExpr, err := dal.GetBlackWhiteList(ctx, s.rdb.Get(), request.ID)
		if err != nil {
			return err
		}
		if reflect.DeepEqual(oldExpr.Scope, request.Scope) {
			if !request.Global {
				for _, scope := range request.Scope {
					wafSvc, err := dal.GetWafService(ctx, tx, uint32(scope))
					if err != nil {
						return err
					}
					err = dal.UpdatetServiceExpr(ctx, tx, wafSvc.ID, request.ID)
					if err != nil {
						return err
					}
					err = s.attachSigleMatchExpression(ctx, request, wafSvc)
					if err != nil {
						return err
					}
				}
			}
		} else if !request.Global {
			err := s.removeGlobalMatchExpression(ctx, request.ID)
			if err != nil {
				return err
			}
			for _, scope := range request.Scope {
				wafSvc, err := dal.GetWafService(ctx, tx, uint32(scope))
				if err != nil {
					return err
				}
				err = dal.UpdatetServiceExpr(ctx, tx, wafSvc.ID, request.ID)
				if err != nil {
					return err
				}
				err = s.attachSigleMatchExpression(ctx, request, wafSvc)
				if err != nil {
					return err
				}
			}
		} else {
			err = s.attachGlobalMatchExpression(ctx, request)
			if err != nil {
				return err
			}
		}

		err = dal.UpdateBlackWhiteList(ctx, tx, &model.MatcherExpr{
			TableBase: model.TableBase{
				ID:     request.ID,
				Status: request.Status,
			},
			Name:   request.Name,
			Scope:  request.Scope,
			Mode:   request.Mode,
			Expr:   request.Expr,
			Global: request.Global,
		})
		return err
	})
	return tErr
}

func (s *WafService) EnableMatchExpression(ctx context.Context, request *MatcherExpr) error {
	tErr := s.rdb.Get().Transaction(func(tx *gorm.DB) error {
		oldExpr, err := dal.GetBlackWhiteList(ctx, s.rdb.Get(), request.ID)
		if err != nil {
			return err
		}
		if reflect.DeepEqual(oldExpr.Scope, request.Scope) {
			// if oldExpr.Scope == request.Scope {
			if !request.Global {
				for _, scope := range request.Scope {
					wafSvc, err := dal.GetWafService(ctx, tx, uint32(scope))
					if err != nil {
						return err
					}
					err = dal.UpdatetServiceExpr(ctx, tx, wafSvc.ID, request.ID)
					if err != nil {
						return err
					}
					err = s.attachSigleMatchExpression(ctx, request, wafSvc)
					if err != nil {
						return err
					}
				}
			}
		} else if !request.Global {
			err := s.removeGlobalMatchExpression(ctx, request.ID)
			if err != nil {
				return err
			}
			for _, scope := range request.Scope {
				wafSvc, err := dal.GetWafService(ctx, tx, uint32(scope))
				if err != nil {
					return err
				}
				err = dal.UpdatetServiceExpr(ctx, tx, wafSvc.ID, request.ID)
				if err != nil {
					return err
				}
				err = s.attachSigleMatchExpression(ctx, request, wafSvc)
				if err != nil {
					return err
				}
			}
		} else {
			err = s.attachGlobalMatchExpression(ctx, request)
			if err != nil {
				return err
			}
		}

		err = dal.EnableBlackWhiteList(ctx, tx, request.ID, request.Status)
		return err
	})
	return tErr
}

func (s *WafService) DeleteMatchExpression(ctx context.Context, id uint32) error {
	tErr := s.rdb.Get().Transaction(func(tx *gorm.DB) error {
		oldExpr, err := dal.GetBlackWhiteList(ctx, s.rdb.Get(), id)
		if err != nil {
			return err
		}
		if oldExpr.Global {
			err = s.removeGlobalMatchExpression(ctx, oldExpr.ID)
			if err != nil {
				return err
			}
		} else {
			for _, scope := range oldExpr.Scope {
				wafSvc, err := dal.GetWafService(ctx, tx, uint32(scope))
				if err != nil {
					if err == gorm.ErrRecordNotFound {
						logging.Get().Info().Msgf("waf service %d has been deleted", scope)
						return dal.DeleteBlackWhiteList(ctx, tx, id)
					}
					return err
				}
				// err = dal.UpdatetServiceExpr(ctx, tx, wafSvc.ID, oldExpr.ID)
				// if err != nil {
				// 	return err
				// }
				err = s.removeSigleMatchExpression(ctx, oldExpr.ID, wafSvc)
				if err != nil {
					return err
				}
			}
		}
		return dal.DeleteBlackWhiteList(ctx, tx, id)
	})
	return tErr
}

func (s *WafService) GetMatchExpression(ctx context.Context, id uint32) (*MatcherExpr, error) {
	expr, err := dal.GetBlackWhiteList(ctx, s.rdb.Get(), id)
	type Result struct {
		Name string
	}
	var results []Result
	var names []string
	s.rdb.Get().Raw("select name from ivan_waf_services where id in ? ", expr.Scope).Scan(&results)
	for _, r := range results {
		names = append(names, r.Name)
	}
	return &MatcherExpr{
		ID:        expr.ID,
		Name:      expr.Name,
		Scope:     expr.Scope,
		Mode:      expr.Mode,
		Expr:      expr.Expr,
		Status:    expr.Status,
		Global:    expr.Global,
		ScopeName: names,
	}, err
}

func (s *WafService) GetMatchExpressions(ctx context.Context, queryOpt *dal.MatchExprQueryOption, offset, limit int) ([]*MatcherExpr, int64, error) {
	exprs, err := dal.GetBlackWhiteLists(ctx, s.rdb.Get(), queryOpt, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountBlackWhiteLists(ctx, s.rdb.Get(), queryOpt)
	if err != nil {
		return nil, 0, err
	}
	type Result struct {
		Name string
	}
	items := make([]*MatcherExpr, 0, len(exprs))
	for _, expr := range exprs {
		var results []Result
		var names []string
		var scopes []uint32
		scopes = expr.Scope
		s.rdb.Get().Raw("select name from ivan_waf_services where id in ? ", scopes).Scan(&results)
		for _, r := range results {
			names = append(names, r.Name)
		}
		items = append(items, &MatcherExpr{
			ID:        expr.ID,
			Name:      expr.Name,
			Scope:     expr.Scope,
			Mode:      expr.Mode,
			Expr:      expr.Expr,
			Status:    expr.Status,
			ScopeName: names,
			Global:    expr.Global,
		})
	}
	return items, cnt, nil
}

func (s *WafService) AddCertFile(ctx context.Context, key string, data []byte) error {
	return dal.AddCerts(ctx, s.rdb.Get(), key, data)
}

func (s *WafService) ListRules(ctx context.Context, lang, name string) ([]RuleGroupResp, error) {
	var count int64
	err := s.rdb.Get().Model(&model.RuleGroup{}).Count(&count).Error
	if err != nil {
		return nil, err
	}
	var newRuleGroups []RuleGroupResp
	if count == 0 {
		var ruleGroups []RuleGroup
		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			return nil, fmt.Errorf("cluster manager not available")
		}
		cm, err := clusterManager.GetHostClient().Clientset.CoreV1().ConfigMaps("tensorsec").Get(ctx, "waf-rules", v1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if data, ok := cm.Data["waf-rules.yaml"]; ok {
			err = yaml.Unmarshal([]byte(data), &ruleGroups)
			if err != nil {
				return nil, err
			}

			var mRuleGroups []model.RuleGroup
			for _, g := range ruleGroups {
				newRuleGroups = append(newRuleGroups, RuleGroupResp{
					CategoryID:  g.CategoryID,
					Category:    g.Category[lang],
					Description: g.Description[lang],
					Rules:       g.Rules,
					Status:      g.Status,
				})
				mRuleGroups = append(mRuleGroups, model.RuleGroup{
					CategoryID:    g.CategoryID,
					CategoryEN:    g.Category["en"],
					CategoryZH:    g.Category["zh"],
					DescriptionEN: g.Description["en"],
					DescriptionZH: g.Description["zh"],
					Status:        g.Status,
				})
			}
			var count int64
			if s.rdb.Get().Model(&model.RuleGroup{}).Count(&count).Error != nil {
				return nil, err
			}
			if count == 0 {
				err := s.rdb.Get().Create(mRuleGroups).Error
				if err != nil {
					return nil, err
				}
			}
			return newRuleGroups, nil
		} else {
			return nil, fmt.Errorf("invalid waf rule configmap")
		}
	} else {
		db := s.rdb.Get().Model(&model.RuleGroup{})
		if name != "" {
			col := "category_zh"
			switch lang {
			case "zh":
				col = "category_zh"
			case "en":
				col = "category_en"
			}
			like := fmt.Sprintf("%s LIKE ?", col)
			db = db.Where(like, "%"+name+"%")
		}
		var mRuleGroups []model.RuleGroup
		err = db.Find(&mRuleGroups).Error
		if err != nil {
			return nil, err
		}
		for _, g := range mRuleGroups {
			r := RuleGroupResp{
				CategoryID: g.CategoryID,
				Status:     g.Status,
			}
			switch lang {
			case "zh":
				r.Category = g.CategoryZH
				r.Description = g.DescriptionZH
			case "en":
				r.Category = g.CategoryEN
				r.Description = g.DescriptionEN
			default:
				r.Category = g.CategoryZH
				r.Description = g.DescriptionZH
			}
			newRuleGroups = append(newRuleGroups, r)
		}

		return newRuleGroups, err
	}

}

func (s *WafService) UpdateRules(ctx context.Context, req *RuleRequest) error {
	var ruleGroups []RuleGroup
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	var err error
	for j := range req.CategoryID {
		err = s.rdb.Get().Model(&model.RuleGroup{}).Where("category_id = ?", req.CategoryID[j]).Update("status", req.Status).Error
		if err != nil {
			return err
		}

	}

	clusterManager.TraverseClient(func(key string, client *assets.Clientset) bool {
		var cm *corev1.ConfigMap
		cm, err = client.Clientset.CoreV1().ConfigMaps("tensorsec").Get(ctx, "waf-rules", v1.GetOptions{})
		if err != nil {
			logging.Get().Err(err).Msgf("get waf rules from cluster: %s", key)
			return false
		}

		if data, exist := cm.Data["waf-rules.yaml"]; exist {
			err = yaml.Unmarshal([]byte(data), &ruleGroups)
			if err != nil {
				logging.Get().Err(err).Msgf("unmarshal waf rules from cluster: %s", key)
				return false
			}
			for i := range ruleGroups {
				for j := range req.CategoryID {
					if ruleGroups[i].CategoryID == req.CategoryID[j] {
						ruleGroups[i].Status = req.Status
					}
				}
			}
			var out []byte
			out, err = yaml.Marshal(ruleGroups)
			if err != nil {
				logging.Get().Err(err).Msgf("marshal waf rules from cluster: %s", key)
				return false
			}
			newCm := cm.DeepCopy()
			newCm.Data["waf-rules.yaml"] = string(out)
			_, err = client.Clientset.CoreV1().ConfigMaps("tensorsec").Update(ctx, newCm, v1.UpdateOptions{})
			return err == nil
		}
		logging.Get().Warn().Msgf("invalid waf rule configmap in cluster: %s", key)
		return true
	})
	if err != nil {
		return fmt.Errorf("invalid waf rule configmap %w", err)
	}
	return nil
}

func (s *WafService) GetAttackLogDetails(ctx context.Context, clusterKey, uuid string) (*AttackLogDetail, error) {
	if len(uuid) == 0 {
		return nil, fmt.Errorf("get waf attack log rsp pkg failed, error : uuid is nil")
	}

	data, err := s.sherlockClient.GetWafDetectionDetail(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("get waf attack details log failed, uuid : %+v, %+v", uuid, err)
	}

	//waf attack detail log
	value := &AttackLogDetail{
		Id:          data.ID,
		RuleId:      data.RuleID,
		Action:      data.Action,
		RuleName:    data.RuleName,
		AttackIp:    data.AttackIP,
		AttackedUrl: data.AttackedURL,
		AttackedApp: data.AttackedApp,
		AttackTime:  data.AttackTime,
		AttackType:  data.AttackType,
		AttackLoad:  data.AttackLoad,
		ReqPkg:      data.ReqPkg,
		RspPkg:      "",
	}

	return value, nil
}

func (s *WafService) GetAttackLogsList(ctx context.Context, filter *AttackLogFilter) ([]AttackLog, string, error) {
	var logs []AttackLog
	var clusters []string
	var attackTypes, actions *[]string
	token := ""

	id := &filter.ServiceId
	url := &filter.AttackUrl
	ip := &filter.AttackIp
	app := &filter.AttackApp
	stime := &filter.StartTime
	etime := &filter.EndTime

	if filter.ServiceId == 0 {
		id = nil
	}
	if len(filter.AttackUrl) == 0 {
		url = nil
	}

	if len(filter.AttackIp) == 0 {
		ip = nil
	}

	if len(filter.AttackApp) == 0 {
		app = nil
	}

	if len(filter.AttackType) == 0 {
		attackTypes = nil
	} else {
		at := strings.Split(filter.AttackType, ",")
		attackTypes = &at
	}

	if len(filter.Action) == 0 {
		actions = nil
	} else {
		act := strings.Split(filter.Action, ",")
		actions = &act
	}

	if filter.StartTime == 0 {
		stime = nil
	}

	if filter.EndTime == 0 {
		etime = nil
	}

	if len(filter.Cluster) == 0 {
		ret, tk, err := s.sherlockClient.FindWafDetections(ctx, id, nil, url, ip, app, attackTypes, actions, stime, etime, filter.Offset, filter.Limit, filter.Token)
		if err != nil {
			return nil, "", fmt.Errorf("get waf attack log list failed, error : %+v", err)
		}
		for i := 0; i < len(ret); i++ {
			log := AttackLog{
				Uuid:         ret[i].ID,
				AttackIp:     ret[i].AttackIP,
				AttackedAddr: ret[i].AttackedURL,
				AttackTime:   ret[i].AttackTime,
				AttackType:   ret[i].AttackType,
				AttackedApp:  ret[i].AttackedApp,
				ClusterKey:   ret[i].ClusterKey,
				Action:       ret[i].Action,
			}
			logs = append(logs, log)
		}
		token = tk
	} else {
		clusters = strings.Split(filter.Cluster, ",")
		for i := 0; i < len(clusters); i++ {
			ret, tk, err := s.sherlockClient.FindWafDetections(ctx, id, &clusters[i], url, ip, app, attackTypes, actions, stime, etime, filter.Offset, filter.Limit, filter.Token)
			if err != nil {
				logging.Get().Error().Msgf("get waf attack log list failed, error : %+v", err)
				continue
			}
			for i := 0; i < len(ret); i++ {
				log := AttackLog{
					Uuid:         ret[i].ID,
					AttackIp:     ret[i].AttackIP,
					AttackedAddr: ret[i].AttackedURL,
					AttackTime:   ret[i].AttackTime,
					AttackType:   ret[i].AttackType,
					AttackedApp:  ret[i].AttackedApp,
					ClusterKey:   ret[i].ClusterKey,
					Action:       ret[i].Action,
				}
				logs = append(logs, log)
			}
			token = tk
		}
	}

	return logs, token, nil
}

func (s *WafService) GetAttackLogRspPkg(ctx context.Context, uuid, length string) (*AttackRspPkg, error) {
	if len(uuid) == 0 {
		return nil, fmt.Errorf("get waf attack log rsp pkg failed, error : uuid is nil")
	}

	data, err := s.sherlockClient.GetWafDetectionDetail(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("get waf attack details log failed, uuid : %+v, %+v", uuid, err)
	}

	alen, _ := strconv.Atoi(length)
	rsp := data.RspPkg
	intact := true

	if alen != 0 && alen < len(rsp) {
		rsp = data.RspPkg[0:alen]
		intact = false
	}

	rspPkg := &AttackRspPkg{
		Uuid:        uuid,
		Intact:      intact,
		ContentType: data.RspContentType,
		RspPkg:      rsp,
	}

	return rspPkg, nil
}

func (s *WafService) GetAttackClassesList(ctx context.Context, lang string) ([]AttackClasses, error) {
	var attackClass []AttackClasses

	isEn := true
	if lang == "zh" {
		isEn = false
	}

	for i := 0; i < len(DefAttackClass); i++ {
		value := AttackClasses{
			Id:         DefAttackClass[i].Id,
			Describe:   DefAttackClass[i].Describe,
			AttackType: DefAttackClass[i].AttackType,
		}
		if isEn {
			value.Describe = DefAttackClass[i].En
		}
		attackClass = append(attackClass, value)
	}

	return attackClass, nil
}
