package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"io"

	"net/http"
	_ "net/http/pprof"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/afex/hystrix-go/hystrix"
	json "github.com/json-iterator/go"
	param2 "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"

	"github.com/gorilla/handlers"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/driftprevention"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/imagetrust"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/immune"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	inject "gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/sidecar"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/util/wait"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
)

var (
	once  sync.Once
	ws    *webHookServer
	wsErr error
)

const resyncInterval = 8 * time.Hour
const (
	mutating = "mutating"
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

	loggedHandler := handlers.CustomLoggingHandler(os.Stdout, mutex, func(writer io.Writer, params handlers.LogFormatterParams) {
		latency := time.Since(params.TimeStamp)
		buf := make([]byte, 0, 100)
		buf = append(buf, "start at: "...)
		buf = append(buf, params.TimeStamp.Format(time.RFC3339)...)
		buf = append(buf, " "...)
		buf = append(buf, "latency: "...)
		buf = append(buf, latency.String()...)
		buf = append(buf, '\n')
		writer.Write(buf)
	})

	ws.Server.Handler = loggedHandler
	ws.Config = config

	err = ws.initDB()
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
	factory := externalversions.NewSharedInformerFactory(hostClient.TensorClientset, resyncInterval)
	err = k8s.InitClusterManager(hostClient, factory, "")
	if err != nil {
		return nil, err
	}
	clsManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, fmt.Errorf("failed to get cluster manager")
	}

	clsManager.Start()
	factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)

	hystrix.ConfigureCommand(mutating, hystrix.CommandConfig{
		Timeout:                int(config.Timeout * 1000),
		MaxConcurrentRequests:  int(config.Concurrency),
		RequestVolumeThreshold: hystrix.DefaultVolumeThreshold,
		SleepWindow:            hystrix.DefaultSleepWindow,
		ErrorPercentThreshold:  hystrix.DefaultErrorPercentThreshold,
	})
	return ws, nil
}

func (s *webHookServer) Start() {
	logging.Get().Debug().Msg("starting server ")

	go func() {
		err := http.ListenAndServe("0.0.0.0:8080", nil)
		if err != nil {
			logging.Get().Err(err).Msg("failed to start profile server")
			return
		}
		logging.Get().Debug().Msg("profile server exited")
	}()

	err := s.Server.ListenAndServeTLS("", "")
	if err != nil {
		logging.Get().Err(err).Msg("failed to start server")
		os.Exit(1)
	}
}

func (s *webHookServer) Stop() {
	err := s.Server.Shutdown(context.TODO())
	if err != nil {
		return
	}
}

func getAdmissionReview(r *http.Request) (*v1.AdmissionReview, int) {
	var body []byte
	if r.Body != nil {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, http.StatusNoContent
		}
		body = data
	}

	if len(body) == 0 {
		return nil, http.StatusNoContent
	}
	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		logging.Get().Err(errors.New("invalid content")).Msgf("Content-Type=%s, expect application/json", contentType)
		return nil, http.StatusInternalServerError
	}
	ar := &v1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, ar); err != nil {
		logging.Get().Err(err).Msg("failed to decode AdmissionReview")
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

	// if cluster param is empty, means that mutating request comes from api-server of host cluster
	if clusterKey == "" {
		clusterKey = s.HostClusterKey
	}

	kind := ar.Request.Kind.Kind
	param := &processors.MutatorParameters{
		Namespace:  ar.Request.Namespace,
		Kind:       kind,
		ClusterKey: clusterKey,
	}

	admissionResponse := &v1.AdmissionResponse{
		Allowed: true,
	}
	var patch []byte

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = hystrix.Do(mutating, func() error {
		patch, err = processors.MutatorChain.Mutate(ctx, param, ar.Request.Object.Raw)
		if err != nil {
			admissionResponse.Allowed = false
			admissionResponse.Result = &metav1.Status{Message: err.Error()}
		} else if len(patch) != 0 {
			patchType := v1.PatchTypeJSONPatch
			admissionResponse.Allowed = true
			admissionResponse.PatchType = &patchType
			admissionResponse.Patch = patch
		} else {
			admissionResponse.Allowed = true
		}
		return nil
	}, func(err error) error {
		logging.Get().Error().Msgf("hystrix err %v", err)
		admissionResponse.Allowed = true
		return nil
	})
	if err != nil {
		logging.Get().Warn().Err(err).Msg("hystrix mutating calling err")
	}

	if len(patch) != 0 {
		patchType := v1.PatchTypeJSONPatch
		admissionResponse.PatchType = &patchType
		admissionResponse.Patch = patch
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
	config, err := k8s.KubeConfig()
	if err != nil {
		logging.Get().Err(err).Msg("init kube config err")
		return
	}

	kubeCli, err := kubernetes.NewForConfig(config)
	if err != nil {
		logging.Get().Err(err).Msg("init kube cli err")
		return
	}
	webHookConfig.KubeCli = kubeCli
	initMutatingChain(s.Config, webHookConfig)
}

func (s *webHookServer) loadHostCluster() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
	defer cancel()

	cluster := model.TensorCluster{}
	err := s.rdb.WithContext(ctx).Where("cluster_type = ?", model.HostCluster).First(&cluster).Error
	s.HostClusterKey = cluster.Key
	return err
}

func (s *webHookServer) initDB() error {
	rdb, err := databases.GetMysqlWithEnv(context.TODO())
	if err != nil || rdb == nil {
		logging.Get().Err(err).Msg("Init rdb error")
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
			logging.Get().Err(errors.New("invalid validator")).Msg(processor)
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
			logging.Get().Err(errors.New("invalid mutator")).Msg(processor)
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
				logging.Get().Info().Msgf("initializing processor %s", name)
				r := method.Call(params)
				ret := r[0].Interface()
				if ret != nil {
					e, isErr := ret.(error)
					if isErr {
						logging.Get().Err(e).Msgf("init processor %s failed", name)
					} else {
						logging.Get().Err(errors.New("unexpected return value")).Msgf("%v", ret)
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
	logging.Get().Info().Msg("Registering processors...")
	microsegmutator.Register()
	driftprevention.Register()
	immune.Register()
	imagetrust.Register()
	inject.Register()
}
