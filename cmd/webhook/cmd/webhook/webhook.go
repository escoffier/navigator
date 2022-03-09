package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	param2 "github.com/oceanicdev/chi-param"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/driftprevention"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/imagetrust"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/imagevalidator"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/immune"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	inject "gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/sidecar"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
)

var (
	once  sync.Once
	ws    *webHookServer
	wsErr error
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
	defaulter     = runtime.ObjectDefaulter(runtimeScheme)
)

type webHookServer struct {
	Server         *http.Server
	URL            string
	Config         *Config
	rdb            *gorm.DB
	HostClusterKey string
}

func NewWebHookServer(config *Config) (*webHookServer, error) {
	//var ws *webHookServer
	once.Do(func() {
		ws, wsErr = newWebHookServer(config)

	})
	return ws, wsErr
}

func newWebHookServer(config *Config) (*webHookServer, error) {
	tlsKeyPair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, err
	}

	ws := &webHookServer{Server: &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: nil,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsKeyPair},
		},
	}}
	mutex := http.NewServeMux()
	mutex.HandleFunc("/mutating", ws.Mutating)
	mutex.HandleFunc("/validating", ws.Validating)
	ws.Server.Handler = mutex
	ws.Config = config

	err = ws.initPG()
	if err != nil {
		return nil, err
	}
	ws.initProcessorChain()

	err = ws.loadHostCluster()
	if err != nil {
		return nil, err
	}

	restConfig, err := k8s.KubeConfig()
	if err != nil {
		return nil, err
	}
	hostClient, err := assets.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	err = k8s.InitClusterManager(hostClient, nil, "")
	if err != nil {
		return nil, err
	}
	clsManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, fmt.Errorf("failed to get cluster manager")
	}

	err = clsManager.Start(context.Background())
	if err != nil {
		return nil, err
	}
	return ws, nil
}

func (s *webHookServer) Start() {

	logging.GetLogger().Debug().Msg("starting server ")
	err := s.Server.ListenAndServeTLS("", "")
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to start server")
		os.Exit(1)
	}
}

func (s *webHookServer) Stop() {
	err := s.Server.Shutdown(context.Background())
	if err != nil {
		return
	}
}

func getAdmissionReview(r *http.Request) (*v1.AdmissionReview, int) {
	var body []byte
	var err error
	if r.Body != nil {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, http.StatusNoContent
		}
	}

	if len(body) == 0 {
		return nil, http.StatusNoContent
	}
	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		logging.GetLogger().Err(errors.New("invalid content")).Msgf("Content-Type=%s, expect application/json", contentType)
		return nil, http.StatusInternalServerError
	}
	ar := &v1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, ar); err != nil {
		logging.GetLogger().Err(err).Msg("failed to decode AdmissionReview")
		return nil, http.StatusInternalServerError
	}
	return ar, http.StatusOK
}

func (s *webHookServer) Mutating(w http.ResponseWriter, r *http.Request) {
	ar, code := getAdmissionReview(r)
	if code != http.StatusOK {
		http.Error(w, "read request body err", code)
		return
	}
	clusterKey, err := param2.QueryString(r, "cluster")
	//host cluster request has no cluster param
	if err != nil {
		logging.GetLogger().Info().Msg("no request param")
	}

	//cluster param is empty mean thant  mutating request comes from api-server of host cluster
	if clusterKey == "" {
		clusterKey = s.HostClusterKey
	}

	kind := ar.Request.Kind.Kind
	param := &processors.MutatorParameters{
		Namespace:  ar.Request.Namespace,
		Kind:       kind,
		ClusterKey: clusterKey,
	}

	var admissionResponse *v1.AdmissionResponse

	patch := processors.MutatorChain.Mutate(param, ar.Request.Object.Raw)

	if patch != nil && len(patch) != 0 {
		patchType := v1.PatchTypeJSONPatch
		admissionResponse = &v1.AdmissionResponse{
			Allowed: true,
			//Result:    result,
			PatchType: &patchType,
			Patch:     patch,
		}
	} else {
		admissionResponse = &v1.AdmissionResponse{Allowed: true}
	}

	admissionReview := v1.AdmissionReview{}
	admissionReview.TypeMeta = ar.TypeMeta
	admissionReview.Response = admissionResponse
	if ar.Request != nil {
		admissionReview.Response.UID = ar.Request.UID
	}

	var resp []byte
	resp, err = json.Marshal(&admissionReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		return
	}

	_, err = w.Write(resp)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func (s *webHookServer) Validating(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var err error
	if r.Body != nil {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request body err", http.StatusNoContent)
			return
		}
	}

	if len(body) == 0 {
		http.Error(w, "empty request body", http.StatusNoContent)
		return
	}
	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		logging.GetLogger().Err(errors.New("invalid content type")).Msgf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}
	var admissionResponse *v1.AdmissionResponse
	ar := v1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		admissionResponse = &v1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}
	clusterKey, err := param2.QueryString(r, "cluster")
	//host cluster request has no cluster param
	if err != nil {
		logging.GetLogger().Info().Msg("no request param")
	}

	if clusterKey == "" {
		clusterKey = s.HostClusterKey
	}
	kind := ar.Request.Kind.Kind

	validateParas := processors.ValidatingParameters{
		ClusterKey: clusterKey,
		Namespace:  ar.Request.Namespace,
		Kind:       kind,
	}
	err = processors.ValidationFilterChain.Validate(validateParas, ar.Request.Object.Raw)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("process object %s:%s err", validateParas.Namespace, validateParas.Kind)
		admissionResponse = &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = &v1.AdmissionResponse{
			Allowed: true,
		}
	}

	admissionReview := v1.AdmissionReview{}
	admissionReview.TypeMeta = ar.TypeMeta
	admissionReview.Response = admissionResponse
	if ar.Request != nil {
		admissionReview.Response.UID = ar.Request.UID
	}

	var resp []byte
	resp, err = json.Marshal(&admissionReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		return
	}

	_, err = w.Write(resp)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func (s *webHookServer) initProcessorChain() {
	webHookConfig := &processors.WebHookConfig{RDB: s.rdb}
	initValidatingChain(s.Config, webHookConfig)
	initMutatingChain(s.Config, webHookConfig)
}

func (s *webHookServer) loadHostCluster() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
	defer cancel()

	cluster := model.TensorCluster{}
	err := s.rdb.WithContext(ctx).Where("name = ?", "default").First(&cluster).Error
	s.HostClusterKey = cluster.Key
	return err
}

func (s *webHookServer) initPG() error {
	rdb, err := databases.GetMysqlWithEnv(context.TODO())
	if err != nil || rdb == nil {
		logging.GetLogger().Err(err).Msg("Init rdb error")
		return err
	}
	s.rdb = rdb
	return nil
}

func initValidatingChain(config *Config, webHookConfig *processors.WebHookConfig) {
	vConfig := &processors.ValidatingConfig{
		IgnoredNameSpaces: config.IgnoredNameSpaces,
	}
	processors.ValidationFilterChain = processors.NewValidatorChain(vConfig)

	for _, processor := range config.Validators {
		v := makeProcessor(processor, webHookConfig)
		if v != nil {
			processors.ValidationFilterChain.AddValidator(v)
		} else {
			logging.GetLogger().Err(errors.New("invalid validator")).Msg(processor)
		}
	}
}

func initMutatingChain(config *Config, webHookConfig *processors.WebHookConfig) {
	processors.MutatorChain = processors.NewMutatorChain(&processors.MutatingConfig{
		IgnoredNameSpaces: config.IgnoredNameSpaces,
	})
	for _, processor := range config.Mutators {
		v := makeProcessor(processor, webHookConfig)
		if v != nil {
			processors.MutatorChain.AddMutator(v)
		} else {
			logging.GetLogger().Err(errors.New("invalid mutator")).Msg(processor)
		}
	}
}

func makeProcessor(name string, webHookConfig *processors.WebHookConfig) interface{} {
	r, ok := processors.ProcessorRegistry[name]
	if ok {
		var va reflect.Value
		v := reflect.New(r).Elem()
		if v.CanAddr() {
			va = v.Addr()
			// find Init function
			method := va.MethodByName("Init")
			if method.IsValid() {
				params := make([]reflect.Value, 1)
				params[0] = reflect.ValueOf(webHookConfig)
				logging.GetLogger().Info().Msgf("Initilizing processor %s", name)
				r := method.Call(params)
				ret := r[0].Interface()

				if ret != nil {
					e, isErr := ret.(error)
					if isErr {
						logging.GetLogger().Err(e).Msgf("init processor %s failed", name)
					} else {
						logging.GetLogger().Err(errors.New("unexpected return value")).Msgf("%v", ret)
					}
					return nil
				}
			}
			return va.Interface()
		}
	}
	return nil
}

func init() {
	// register all processors here
	logging.GetLogger().Info().Msg("Registering processors...")
	imagevalidator.Register()
	microsegmutator.Register()
	driftprevention.Register()
	immune.Register()
	imagetrust.Register()
	imagetrust.Register()
	inject.Register()
}
