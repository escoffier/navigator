package defense

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/olivere/elastic/v7"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	pkgelastic "gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/logging"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	v1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
)

const (
	ImageListPath = "/api/v1/images/sampleList"
	RegistryPath  = "/api/v1/register/registry/"
)

var (
	instance  *TensorDefenseService
	rlOnce    sync.Once
	usingGrpc = false
)

type Signal struct {
	ID           string `json:"id,omitempty"`
	Cluster      string `json:"cluster,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	ResourceType string `json:"nodeType,omitempty"`
	Resource     string `json:"nodeKey,omitempty"`
	Category     string `json:"category,omitempty"`
	Severity     uint32 `json:"severity,omitempty"`
	Description  string `json:"description,omitempty"`
	Timestamp    int64  `json:"timestamp,omitempty"`
}

type RegistryInfo struct {
	UserName string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

func InitDefenseService(rdb *databases.RDBInstance, esCli *pkgelastic.ESClient, scannerURL string, stream rpcstream.MessageStream) error {
	rlOnce.Do(func() {
		instance = &TensorDefenseService{
			rdb:        rdb,
			EsCli:      esCli,
			scannerURL: scannerURL,
			stream:     stream,
		}
		instance.CheckAlertEvents()
	})
	return nil
}

type TensorDefenseService struct {
	rdb        *databases.RDBInstance
	EsCli      *pkgelastic.ESClient
	scannerURL string
	stream     rpcstream.MessageStream
}

func GetDefenseService(_ context.Context) (*TensorDefenseService, bool) {
	return instance, instance != nil
}

func (s *TensorDefenseService) AddBaitService(ctx context.Context, bait *model.BaitService) error {
	image, err := dal.GetBaitImageById(ctx, s.rdb.Get(), bait.BaitId)
	if err != nil {
		logging.Get().Err(err).Msg("get image failed")
		return err
	}
	if image == nil {
		return fmt.Errorf("not found image: %d", bait.BaitId)
	}

	registry, err := s.GetImageRepoInfo(ctx, bait.RegistryId)
	if err != nil {
		return err
	}

	bait.Prefix = image.EventPrefix
	if usingGrpc {
		err = s.addBaitService(ctx, bait, image.Ports, registry, image.EventPrefix)
	} else {
		err = s.addBaitServiceToKube(ctx, bait, image.Ports, registry, image.EventPrefix)
	}

	if err != nil {
		return err
	}
	err = dal.InsertBaitService(ctx, s.rdb.Get(), bait)
	if err != nil {
		baitName, _ := getHoneyspotName(bait)
		if usingGrpc {
			s.deleteBaitService(ctx, bait.ClusterKey, bait.Namespace, baitName)
		} else {
			s.deleteBaitServiceFromKube(ctx, bait.ClusterKey, bait.Namespace, baitName)
		}
		return err
	}
	return nil
}

func (s *TensorDefenseService) GetBaitService(ctx context.Context, option *dal.BaitsQueryOption) (*model.BaitService, error) {
	baitServices, err := dal.GetBaitServices(ctx, s.rdb.GetReadDB(), option, 0, 1)
	if err != nil {
		return nil, err
	}
	if len(baitServices) == 0 {
		return nil, fmt.Errorf("not found bait service")
	}

	return baitServices[0], nil
}

func (s *TensorDefenseService) GetBaitServices(ctx context.Context, option *dal.BaitsQueryOption, limit, offset int) ([]*model.BaitService, error) {
	var baitServices []*model.BaitService
	var err error
	baitServices, err = dal.GetBaitServices(ctx, s.rdb.GetReadDB(), option, offset, limit)
	if err != nil {
		return nil, err
	}
	return baitServices, nil
}

func (s *TensorDefenseService) DeleteBaitService(ctx context.Context, id uint32) error {
	queryOpt := dal.BaitsQuery()
	queryOpt.WithId(id)

	baitService, err := dal.GetBaitService(ctx, s.rdb.Get(), queryOpt)
	if err != nil {
		return err
	}
	baitName, err := getHoneyspotName(baitService)
	if err != nil {
		return err
	}
	if usingGrpc {
		s.deleteBaitService(ctx, baitService.ClusterKey, baitService.Namespace, baitName)
	} else {
		err = s.deleteBaitServiceFromKube(ctx, baitService.ClusterKey, baitService.Namespace, baitName)
	}

	if err != nil {
		return err
	}
	return dal.DeleteBaitServiceById(ctx, s.rdb.Get(), id)
}

func (s *TensorDefenseService) UpdateBaitService(ctx context.Context, bait *model.BaitService) error {
	// only update bait name
	return dal.UpsertBaitService(ctx, s.rdb.Get(), bait)
}

func (s *TensorDefenseService) addBaitServiceToKube(ctx context.Context, bait *model.BaitService, ports []int32, registry *RegistryInfo, prefix string) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(bait.ClusterKey)
	if !ok {
		return fmt.Errorf("clientset not available")
	}

	honeyspotName, err := getHoneyspotName(bait)
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("ports: %v", ports)

	servicePorts := make([]v1.ServicePort, 0, len(ports))
	for _, p := range ports {
		servicePorts = append(servicePorts, v1.ServicePort{
			Port:       p,
			TargetPort: p,
		})
	}

	secrets := []v1.ImagePullSecret{
		{
			UserName: registry.UserName,
			Password: registry.Password,
			Server:   registry.URL,
		},
	}

	resourceName := fmt.Sprintf("%s-%s", prefix, bait.ResourceName)
	honeypot := &v1.Honeypot{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: bait.Namespace,
			Name:      honeyspotName,
		},
		Spec: v1.HoneypotSpec{
			ClusterKey:  bait.ClusterKey,
			WorkLoad:    resourceName,
			Ports:       servicePorts,
			Service:     bait.ResourceName,
			Image:       bait.Image,
			Secrets:     secrets,
			Replica:     bait.Replica,
			OutboundOff: bait.OutboundOff,
		},
	}
	logging.Get().Info().Msgf("image: %s", bait.Image)
	_, err = clientset.TensorClientset.DefenseV1().Honeypots(bait.Namespace).Create(ctx, honeypot, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (s *TensorDefenseService) addBaitService(ctx context.Context, bait *model.BaitService, ports []int32, registry *RegistryInfo, prefix string) error {
	honeyspotName, err := getHoneyspotName(bait)
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("ports: %v", ports)

	servicePorts := make([]*pb.ServicePort, 0, len(ports))
	for _, p := range ports {
		servicePorts = append(servicePorts, &pb.ServicePort{
			Port:       p,
			TargetPort: p,
		})
	}

	secrets := []*pb.ImagePullSecret{
		{
			UserName: registry.UserName,
			Password: registry.Password,
			Server:   registry.URL,
		},
	}

	resourceName := fmt.Sprintf("%s-%s", prefix, bait.ResourceName)
	resp, err := s.stream.CreateHoneySpot(ctx, bait.ClusterKey, &pb.HoneySpotReq{
		Namespace:   bait.Namespace,
		Name:        honeyspotName,
		WorkLoad:    resourceName,
		Ports:       servicePorts,
		Service:     bait.ResourceName,
		Image:       bait.Image,
		Secrets:     secrets,
		Replica:     bait.Replica,
		OutboundOff: bait.OutboundOff,
	})
	if err != nil {
		logging.Get().Err(err).Msg("create honeyspot err")
	} else {
		logging.Get().Info().Msgf("create honeyspot reponse: %s", resp.String())
	}
	return nil
}

func (s *TensorDefenseService) updateBaitServiceToKube(ctx context.Context, bait *model.BaitService) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(bait.ClusterKey)
	if !ok {
		return fmt.Errorf("clientset not available")
	}
	patchData := map[string]interface{}{
		"spec": map[string]interface{}{
			"image":    bait.Image,
			"workload": bait.ResourceName,
			"service":  bait.ResourceName,
		},
	}
	patchByte, err := json.Marshal(patchData)
	if err != nil {
		return err
	}
	logging.Get().Info().Msgf("patch data : %+v", string(patchByte))

	baitName, err := getHoneyspotName(bait)
	if err != nil {
		return err
	}

	_, err = clientset.TensorClientset.DefenseV1().Honeypots(bait.Namespace).
		Patch(ctx, baitName, types.MergePatchType, patchByte, metav1.PatchOptions{})
	return err
}

func (s *TensorDefenseService) deleteBaitServiceFromKube(ctx context.Context, clusterKey, namespace, name string) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(clusterKey)
	if !ok {
		return fmt.Errorf("clientset not available")
	}

	err := clientset.TensorClientset.DefenseV1().Honeypots(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	return err
}

func (s *TensorDefenseService) deleteBaitService(ctx context.Context, clusterKey, namespace, name string) error {
	err := s.stream.DeleteHoneySpot(ctx, clusterKey, namespace, name)
	return err
}

func (s *TensorDefenseService) GetBaitServiceFromKube(ctx context.Context, clusterKey string, namespace, name string) (*v1.Honeypot, error) {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(clusterKey)
	if !ok {
		return nil, fmt.Errorf("clientset not available")
	}
	honeypot, err := clientset.TensorClientset.DefenseV1().Honeypots(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return honeypot, nil
}

func getBaitServicesFromKube(ctx context.Context, option *dal.BaitsQueryOption) ([]v1.Honeypot, error) {
	clusterKey, ok := option.GetClusterOption()
	if !ok {
		return nil, fmt.Errorf("invalid cluster key")
	}
	ns, ok := option.GetNamespace()
	if !ok {
		ns = ""
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(clusterKey)
	if !ok {
		return nil, fmt.Errorf("clientset not available")
	}
	honeypots, err := clientset.TensorClientset.DefenseV1().Honeypots(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return honeypots.Items, nil
}

func getHoneyspotName(baitService *model.BaitService) (string, error) {
	if baitService == nil || baitService.Name == "" {
		return "", fmt.Errorf("invalid bait service")
	}
	return fmt.Sprintf("honeyspot-%d", baitService.ID), nil
}

func (s *TensorDefenseService) CountBaitServices(ctx context.Context, option *dal.BaitsQueryOption) (int64, error) {
	cnt, err := dal.CountBaitServices(ctx, s.rdb.GetReadDB(), option)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (s *TensorDefenseService) GetBaitImages(ctx context.Context, offset, limit int) ([]*model.BaitImages, error) {
	baitImages, err := dal.GetBaitImages(ctx, s.rdb.GetReadDB(), offset, limit)
	if err != nil {
		return nil, err
	}
	return baitImages, nil
}

func (s *TensorDefenseService) CountBaitImages(ctx context.Context) (int64, error) {
	cnt, err := dal.CountBaitImages(ctx, s.rdb.GetReadDB())
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (s *TensorDefenseService) GetBaitImageByID(ctx context.Context, id uint32) (*model.BaitImages, error) {
	baitImages, err := dal.GetBaitImageById(ctx, s.rdb.GetReadDB(), id)
	if err != nil {
		return nil, err
	}
	return baitImages, nil
}

func (s *TensorDefenseService) GetAlertEvent(ctx context.Context, clusterKey, namespace, resource string, limit int, startTime int64) ([]*Signal, error) {
	es, err := s.EsCli.Get()
	if err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 200
	}

	logging.Get().Info().Msgf("start time: %d, end time: %d", startTime, time.Now().UnixMilli())

	boolQuery := elastic.NewBoolQuery().Filter(
		elastic.NewTermQuery("ruleKey.category.keyword", "Watson"),
		elastic.NewTermQuery("scope.cluster.id", clusterKey),
		elastic.NewTermQuery("scope.namespace.name.keyword", namespace),
		elastic.NewTermQuery("scope.resource.name.keyword", fmt.Sprintf("%s(Deployment)", resource)),
		elastic.NewRangeQuery("createdAt").Gte(startTime).Lte(time.Now().UnixMilli()),
	)

	// debug
	src, _ := boolQuery.Source()
	logging.Get().Debug().Interface("source", src).Msg("QSL")

	// TODO: 应该不直接查询es，调用sherlockAPI
	signalsResp, err := es.Search("signals,signals-*,signals_*").Query(boolQuery).
		FetchSourceContext(elastic.NewFetchSourceContext(true).Include("severity")).
		Sort("createdAt", false).Size(limit).Do(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: aggs count
	result := make([]*Signal, 0, len(signalsResp.Hits.Hits))
	for _, hit := range signalsResp.Hits.Hits {
		s := map[string]uint32{}
		if err := json.Unmarshal(hit.Source, &s); err != nil {
			logging.Get().Warn().Err(err).Msg("json.Unmarshal")
			continue
		}

		result = append(result, &Signal{
			Severity: s["severity"],
		})
	}

	return result, nil

	// logging.Get().Info().Msgf("start time: %d, end time: %d", startTime, time.Now().Unix())
	// req := &pb.GetSignalsReq{
	// 	OffsetSignalID: "",
	// 	SortOrder:      pb.SortOrder_Desc,
	// 	Limit:          limit,
	// 	Filter: map[string]string{
	// 		"cluster":      clusterKey,
	// 		"namespace":    namespace,
	// 		"nodeType":     "Deployment",
	// 		"nodeKey":      resource,
	// 		"ruleModule":   "ContainerSecurity",
	// 		"ruleCategory": "Watson",
	// 	},
	// 	TimeFilter: &pb.TimeFilter{StartTimestamp: startTime, EndTimestamp: time.Now().UnixMilli()},
	// 	Lang:       string(lang.Language(ctx)),
	// }
	// resp, err := s.EsCli.GetSignals(ctx, req)
	// if err != nil {
	// 	return nil, err
	// }
	// logging.Get().Debug().Msgf("got %d signals", len(resp.Signals))
	// result := make([]*Signal, 0, len(resp.Signals))
	// for _, item := range resp.Signals {
	// 	result = append(result, &Signal{
	// 		Severity: item.Rule.Severity,
	// 	})
	// }
	// return result, nil
}

type ImageDetail struct {
	RegistryID int    `json:"registryId"`
	Image      string `json:"image"`
}

func (s *TensorDefenseService) GetBaitImageRepoInfo(ctx context.Context, imageName string) ([]*ImageDetail, error) {
	type ImageBase struct {
		FullRepoName      string `json:"full_repo_name"`
		Library           string `json:"library"`
		Tag               string `json:"tags"`
		RegistryID        int    `json:"registry_id"`
		RegistryDeletedAt int64  `json:"registry_deleted_at"`
	}

	var tag string
	names := strings.SplitN(imageName, ":", 2)
	if len(names) < 1 {
		return nil, fmt.Errorf("invalid image name %s", imageName)
	}
	if len(names) == 1 {
		tag = "latest"
	} else {
		tag = names[1]
	}

	url := fmt.Sprintf("%s%s%s%s", s.scannerURL, ImageListPath, "?search=", names[0])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logging.Get().Err(err).Msg("create request failed")
		return nil, err
	}
	var images []*ImageDetail
	var matchedImages []*ImageBase
	err = util.HTTPRequest(ctx, httputil.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return errors.Errorf("request scanner imageList error: %v", err)
		}
		var body []byte
		if resp.Body == nil {
			return errors.Errorf("request scanner imageList resp body is nil")
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("read resp.body error: %v", err)
		}

		if resp.StatusCode >= http.StatusBadRequest {
			err = errors.Errorf("request scanner err. resp data: %s", string(body))
			return err
		}

		var rawResp response.HTTPEnvelope
		err = json.Unmarshal(body, &rawResp)
		if err != nil {
			return err
		}
		if len(rawResp.Data.Items) > 0 {
			err = json.Unmarshal(rawResp.Data.Items, &matchedImages)
			if err != nil {
				return err
			}
			for _, item := range matchedImages {
				if tag != item.Tag || item.RegistryDeletedAt > 0 {
					continue
				}
				if item.RegistryDeletedAt > 0 {
					continue
				}

				library := removePrefix(item.Library)
				images = append(images, &ImageDetail{
					RegistryID: item.RegistryID,
					Image:      fmt.Sprintf("%s/%s:%s", library, item.FullRepoName, item.Tag),
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return images, nil
}

func (s *TensorDefenseService) GetImageRepoInfo(ctx context.Context, registryID int) (*RegistryInfo, error) {

	url := fmt.Sprintf("%s%s%d", s.scannerURL, RegistryPath, registryID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logging.Get().Err(err).Msg("create request failed")
		return nil, err
	}

	var registry RegistryInfo
	err = util.HTTPRequest(ctx, httputil.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return errors.Errorf("request scanner imageList error: %v", err)
		}
		var body []byte
		if resp.Body == nil {
			return errors.Errorf("request scanner imageList resp body is nil")
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("read resp.body error: %v", err)
		}

		if resp.StatusCode >= http.StatusBadRequest {
			err = errors.Errorf("request scanner err. resp data: %s", string(body))
			return err
		}

		var rawResp response.HTTPEnvelope
		err = json.Unmarshal(body, &rawResp)
		if err != nil {
			return err
		}
		if rawResp.Data == nil {
			return fmt.Errorf("resp data is empty")
		}

		if len(rawResp.Data.Item) > 0 {
			err = json.Unmarshal(rawResp.Data.Item, &registry)
			if err != nil {
				return err
			}
		}
		return err
	})

	if err != nil {
		return nil, err
	}

	logging.Get().Debug().Msgf("registry: %+v", registry)
	return &registry, nil
}

func (s *TensorDefenseService) CheckAlertEvents() {
	stopChan := make(chan struct{})
	go func() {
		wait.Until(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			queryOpt := dal.BaitsQuery()
			baitServices, err := s.GetBaitServices(ctx, queryOpt, -1, -1)
			if err != nil {
				logging.Get().Err(err).Msg("failed to get bait services")
				return
			}
			for _, bait := range baitServices {
				prefixName := fmt.Sprintf("%s-%s", bait.Prefix, bait.ResourceName)

				events, err := s.GetAlertEvent(ctx, bait.ClusterKey, bait.Namespace, prefixName, 1, bait.CreatedAt.UnixMilli())
				if err != nil {
					logging.Get().Err(err).Msg("failed to get bait events")
					continue
				}
				haveAlerts := false
				if len(events) > 0 {
					haveAlerts = true
				}

				logging.Get().Info().Msgf("update bait service alerts flag %t", haveAlerts)
				err = dal.UpdateBaitServiceAlert(ctx, s.rdb.Get(), bait.ID, haveAlerts)
				if err != nil {
					logging.Get().Err(err).Msg("failed to update bait services")
					continue
				}
			}
		}, time.Second*120, stopChan)
	}()
}

func removePrefix(url string) string {
	if strings.Contains(url, "https://") {
		return url[8:]
	} else if strings.Contains(url, "http://") {
		return url[7:]
	} else {
		return url
	}
}

func (s *TensorDefenseService) DeleteAllBaitServicesFromKube(ctx context.Context, clusterKey string) error {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return fmt.Errorf("cluster manager not available")
	}
	clientset, ok := clusterManager.GetClient(clusterKey)
	if !ok {
		return fmt.Errorf("clientset not available")
	}

	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, ns := range nsList.Items {
		err = clientset.TensorClientset.DefenseV1().Honeypots(ns.Name).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
	}

	return err
}

func init() {
	useGrpc := os.Getenv("USING_GRPC")
	if useGrpc == "true" {
		usingGrpc = true
	}
}
