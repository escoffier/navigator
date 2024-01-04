package waf

import (
	"encoding/json"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	listerv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	v1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/waf.security.io/v1alpha1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
	informerv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions/waf.security.io/v1alpha1"
	listerv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/waf.security.io/v1alpha1"
)

const (
	moduleKey   = "module"
	moduleName  = "waf"
	maxRetries  = 15
	wkLoadIndex = "workloadIndex"
)

var log = logging.Get().With().Str("module", "waf").Logger()

type WafController struct {
	wafServiceInformer cache.SharedIndexInformer
	configInformer     cache.SharedIndexInformer
	wafServiceLister   listerv1alpha1.ServiceLister
	configLister       listerv1.ConfigMapLister
	podWatcher         *nodeinfo.NodePodsWatcher
	wafServiceSynced   cache.InformerSynced
	configSynced       cache.InformerSynced
	queue              workqueue.RateLimitingInterface
	rootNamespace      string
	wafRules           []Rule
	baseConfig         WafConfig
	blackwhitelists    []v1alpha1.MatchExpression
	agentCliet         Client
}

type WafConfig struct {
	ExcludedFileTypes []string `json:"excluded_file_type"`
	DetectHeaders     []string `json:"detect_headers"`
}

type RuleGroup struct {
	CategoryID string `json:"category_id" yaml:"category_id"`
	Rules      []Rule `json:"rules"`
	Status     int    `json:"status"`
}

func NewWafController(clientset *versioned.Clientset, factory informers.SharedInformerFactory,
	crdFactory externalversions.SharedInformerFactory, podWatcher *nodeinfo.NodePodsWatcher, cli Client) *WafController {
	// wafServiceInformer := crdFactory.Waf().V1alpha1().Services().Informer()
	wafServiceInformer := informerv1alpha1.NewServiceInformer(clientset, v1.NamespaceAll, time.Hour*10, cache.Indexers{})
	wafServiceInformer.GetIndexer().AddIndexers(cache.Indexers{
		wkLoadIndex: func(obj interface{}) ([]string, error) {
			svc := obj.(*v1alpha1.Service)
			wl := svc.Spec.Workload
			return []string{wl.Kind + "/" + wl.Namespace + "/" + wl.Name}, nil
		},
	})

	configInformer := factory.Core().V1().ConfigMaps().Informer()

	controller := &WafController{
		wafServiceInformer: wafServiceInformer,
		configInformer:     configInformer,
		wafServiceLister:   listerv1alpha1.NewServiceLister(wafServiceInformer.GetIndexer()),
		configLister:       factory.Core().V1().ConfigMaps().Lister(),
		wafServiceSynced:   wafServiceInformer.HasSynced,
		configSynced:       configInformer.HasSynced,
		queue:              workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "waf-queue"),
		podWatcher:         podWatcher,
		agentCliet:         cli,
	}
	controller.agentCliet.SetController(controller)

	wafServiceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.AddWafService,
		UpdateFunc: controller.UpdateWafService,
		DeleteFunc: controller.DeleteWafService,
	})
	configInformer.AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: func(obj interface{}) bool {
			meta, err := meta.Accessor(obj)
			if err != nil {
				return false
			}
			labels := meta.GetLabels()
			app, ok := labels["app"]
			if ok {
				if app == "waf" {
					return true
				}
			}
			return false
		},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    controller.AddConfig,
			UpdateFunc: controller.UpdateConfig,
			DeleteFunc: controller.DeleteConfig,
		},
	})

	podWatcher.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.AddPod,
		DeleteFunc: controller.DeletePod,
	})
	return controller
}

func (c *WafController) AddWafService(obj interface{}) {
	wafService := obj.(*v1alpha1.Service)
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(wafService)
	if err != nil {
		log.Info().Err(err).Msg("invalid waf service")
		return
	}

	c.queue.Add(key)
}

func (c *WafController) UpdateWafService(oldObj, newObj interface{}) {
	wafService := newObj.(*v1alpha1.Service)
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(wafService)
	if err != nil {
		return
	}

	c.queue.Add(key)
}

func (c *WafController) DeleteWafService(obj interface{}) {
	service := obj.(*v1alpha1.Service)
	wl := service.Spec.Workload
	pods, err := c.podWatcher.GetPodByOwnder(wl.Kind, wl.Namespace, wl.Name)
	if err != nil {
		log.Err(err).Msgf("find pod of waf service %s", service.Name)
		return
	}
	if len(pods) > 0 {
		err = c.agentCliet.DeleteWaf(pods)
		if err != nil {
			logging.Get().Err(err).Msgf("delete waf service %s", service.Name)
			return
		}
	}

	// key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(wafService)
	// if err != nil {
	// 	return
	// }

	// c.queue.Add(key)
}

func (c *WafController) AddConfig(obj interface{}) {
	configMap := obj.(*v1.ConfigMap)
	err := c.loadWafConfig(configMap)
	if err != nil {
		log.Warn().Msgf("load waf config %v", err)
		return
	}
}

func (c *WafController) UpdateConfig(oldObj, newObj interface{}) {
	configMap := newObj.(*v1.ConfigMap)
	// if configMap.Name == "waf-rules" {
	// 	c.loadConfig(configMap)
	// } else if configMap.Name == "waf-blackwhitelists" {
	// 	c.loadBlackWhiteList(configMap)
	// }
	err := c.loadWafConfig(configMap)
	if err != nil {
		log.Warn().Msgf("load waf config %v", err)
		return
	}
}

func (c *WafController) DeleteConfig(obj interface{}) {
	log.Warn().Msgf("delete waf config will break waf")
}

func (c *WafController) AddPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod.Status.PodIP == "" {
		return
	}
	name, kind := util.GetOwnerOfPod(pod)
	key := kind + "/" + pod.Namespace + "/" + name
	services, err := c.wafServiceInformer.GetIndexer().ByIndex(wkLoadIndex, key)
	if err != nil {
		logging.Get().Err(err).Msgf("not found waf service")
		return
	}
	log.Info().Msgf("add pod %s", pod.Namespace+"/"+pod.Name)
	for _, svc := range services {
		wafService := svc.(*v1alpha1.Service)
		log.Info().Msgf("update waf service %s by pod", wafService.Namespace+"/"+wafService.Name)
		c.AddWafService(svc)
	}
}

func (c *WafController) UpdatePod(oldObj, newObj interface{}) {
	c.AddPod(newObj)
}

func (c *WafController) DeletePod(obj interface{}) {
	pod := obj.(*v1.Pod)
	name, kind := util.GetOwnerOfPod(pod)
	key := kind + "/" + pod.Namespace + "/" + name
	logging.Get().Info().Msgf("delete pod %s", key)
	services, err := c.wafServiceInformer.GetIndexer().ByIndex(wkLoadIndex, key)
	if err != nil {
		log.Err(err).Msgf("")
		return
	}

	for _, svc := range services {
		wafService := svc.(*v1alpha1.Service)
		log.Info().Msgf("delete waf rule for service %s", wafService.Namespace+"/"+wafService.Name)
		// c.AddWafService(svc)
	}
}

func (rg *WafController) handleErr(err error, key interface{}) {
	if err == nil {
		rg.queue.Forget(key)
		return
	}
	if rg.queue.NumRequeues(key) < maxRetries {
		log.Err(err).Str(moduleKey, moduleName).Msgf("Error syncing policy rule, retrying %s", key)
		rg.queue.AddRateLimited(key)
		return
	}

	log.Warn().Str(moduleKey, moduleName).Msgf("Dropping policy rule %q out of the queue: %v", key, err)
	rg.queue.Forget(key)
}

func (c *WafController) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	policyName := key.(string)
	err := c.syncWafService(policyName)
	c.handleErr(err, key)

	return true
}

func (c *WafController) worker() {
	log.Info().Str(moduleKey, moduleName).Msg("start worker")
	for c.processNextItem() {
	}
}

func (c *WafController) Run(stopChan chan struct{}) {
	go func() {
		c.wafServiceInformer.Run(stopChan)
	}()

	if !cache.WaitForNamedCacheSync("waf-service", stopChan, c.wafServiceSynced, c.configSynced) {
		return
	}
	wait.Until(c.worker, time.Second, stopChan)

}

func (c *WafController) syncWafService(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Err(err).Msg("invalid meta key")
		return err
	}
	log.Info().Msgf("sync waf service: %s/%s", namespace, name)
	wafSvc, err := c.wafServiceLister.Services(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	log.Info().Msgf("waf service %v", wafSvc)
	wl := wafSvc.Spec.Workload
	pods, err := c.podWatcher.GetPodByOwnder(wl.Kind, wl.Namespace, wl.Name)
	if err != nil {
		log.Err(err).Msgf("found pod by owner %v", wl)
		return nil
	}
	if len(pods) > 0 {
		config, err := c.generateConfig(wafSvc)
		if err != nil {
			log.Info().Err(err).Msgf("sync waf service %s", wafSvc.Name)
			return nil
		}
		c.agentCliet.SendWafMessage(config, pods)
		// for _, pod := range pods {
		// 	config.PodIP = pod.Status.PodIP
		// }
	}
	return nil
}

func (c *WafController) loadBlackWhiteList(configMap *v1.ConfigMap) error {
	if data, exist := configMap.Data["expr"]; exist {
		log.Info().Msgf("blackwhite list : %s", data)
		bwList := []v1alpha1.MatchExpression{}
		err := json.Unmarshal([]byte(data), &bwList)
		if err != nil {
			return err
		}
		c.blackwhitelists = bwList
		log.Info().Msgf("BlackWhiteList %+v", c.blackwhitelists)
	}
	return nil
}

func (c *WafController) loadWafConfig(configMap *v1.ConfigMap) error {
	if configMap.Name == "waf-rules" {
		c.loadConfig(configMap)
		c.TriggerAllSync()
		return nil
	} else if configMap.Name == "waf-blackwhitelists" {
		c.loadBlackWhiteList(configMap)
		c.TriggerAllSync()
		return nil
	}
	c.wafServiceLister.List(labels.Everything())
	return fmt.Errorf("unexpected waf configmap")
}

func (c *WafController) loadConfig(configMap *v1.ConfigMap) error {
	if configData, ok := configMap.Data["config"]; ok {
		err := json.Unmarshal([]byte(configData), &c.baseConfig)
		if err != nil {
			return fmt.Errorf("parse waf config: %w", err)
		}
		log.Info().Msgf("waf config: %s", configData)
		// logging.Get().Info().Msgf("waf config: %s", configData)
	}

	if ruleData, ok := configMap.Data["waf-rules.yaml"]; ok {
		var ruleGroups []RuleGroup
		err := yaml.Unmarshal([]byte(ruleData), &ruleGroups)
		if err != nil {
			log.Err(err).Msg("unmarshal waf rule ")
			return err
		}
		rs := make([]Rule, 0, 50)
		for _, g := range ruleGroups {
			if g.Status == 0 {
				rs = append(rs, g.Rules...)
			}
		}
		log.Info().Msgf("load %d rules", len(rs))
		c.wafRules = rs
	}

	return nil
}

func (c *WafController) generateConfig(service *v1alpha1.Service) (*Config, error) {
	var bwList []v1alpha1.MatchExpression
	for _, bw := range service.Spec.BlackWhireLists {
		if bw.Status == 0 {
			bwList = append(bwList, bw)
		}
	}
	for i := range c.blackwhitelists {
		if c.blackwhitelists[i].Status == 0 {
			bwList = append(bwList, c.blackwhitelists[i])
		}
	}

	config := &Config{
		MsgType:           7,
		Mode:              service.Spec.Mode,
		ClusterKey:        service.Spec.Workload.ClusterKey,
		Namespace:         service.Spec.Workload.Namespace,
		Kind:              service.Spec.Workload.Kind,
		WorkLoadName:      service.Spec.Workload.Name,
		Name:              service.Name,
		ServiceID:         service.Spec.ServiceID,
		Rules:             c.wafRules,
		BlackWhireLists:   bwList,
		ExcludedFileTypes: c.baseConfig.ExcludedFileTypes,
		DetectHeaders:     c.baseConfig.DetectHeaders,
		Domain:            service.Spec.HostNames,
		Uri:               service.Spec.Uri.Prefix,
		Post:              EventPostConf{},
	}

	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("generate config %v", err)
	}
	log.Info().Msgf("generate config: %s", data)
	return config, nil
}

func (c *WafController) TriggerAllSync() error {
	log.Info().Msg("resync waf service")
	all, err := c.wafServiceLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, wafService := range all {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(wafService)
		if err != nil {
			log.Err(err).Msg("invalid waf service")
			return err
		}

		c.queue.Add(key)
	}
	return nil
}
