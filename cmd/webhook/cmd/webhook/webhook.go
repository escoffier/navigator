package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/driftprevention"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/imagevalidator"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"io/ioutil"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"net/http"
	"os"
	"reflect"
	"sync"
)

var (
	once sync.Once
	ws   *webHookServer
	err  error
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
	defaulter     = runtime.ObjectDefaulter(runtimeScheme)
)

type webHookServer struct {
	Server *http.Server
	URL    string
	Config *Config
}

func NewWebHookServer(config *Config) (*webHookServer, error) {
	//var ws *webHookServer
	once.Do(func() {
		ws, err = newWebHookServer(config)

	})
	return ws, err
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
	ws.initProcessorChain()
	return ws, nil
}

func (s *webHookServer) Start() {
	log.Debug("starting server ")
	err := s.Server.ListenAndServeTLS("", "")
	if err != nil {
		log.Errorf("failed to start server: %v", err)
		os.Exit(1)
	}
}

func (s *webHookServer) Stop() {
	s.Server.Shutdown(context.Background())
}

func getAdmissionReview(r *http.Request) *v1.AdmissionReview {
	var body []byte
	if r.Body != nil {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			//http.Error(w, "read request body err", http.StatusNoContent)
			return nil
		}
	}

	if len(body) == 0 {
		//http.Error(w, "empty request body", http.StatusNoContent)
		return nil
	}
	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Errorf("Content-Type=%s, expect application/json", contentType)
		//http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return nil
	}
	//var admissionResponse *v1beta1.AdmissionResponse
	ar := &v1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, ar); err != nil {
		log.Errorf("failed to decode AdmissionReview %v", err)
		return nil
	}
	//review, _ := json.MarshalIndent(&ar, "", "  ")
	//fmt.Println(string(review))

	return ar
}

func (s *webHookServer) Mutating(w http.ResponseWriter, r *http.Request) {
	ar := getAdmissionReview(r)
	if ar == nil {
		http.Error(w, "read request body err", http.StatusInternalServerError)
		return
	}
	kind := ar.Request.Kind.Kind
	param := &processors.MutatorParameters{
		Namespace: ar.Request.Namespace,
		Kind:      kind,
		Cluster:   "default",
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
		log.Errorf("Content-Type=%s, expect application/json", contentType)
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
	//review, _ := json.MarshalIndent(&ar, "", "  ")
	//fmt.Println(string(review))

	kind := ar.Request.Kind.Kind

	validateParas := processors.ValidatingParameters{
		Namespace: ar.Request.Namespace,
		Kind:      kind,
	}
	err = processors.ValidationFilterChain.Validate(validateParas, ar.Request.Object.Raw)
	if err != nil {
		log.Errorf("process err %v", err)
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
	initValidatingChain(s.Config)
	initMutatingChain(s.Config)

	//config := &processors.ValidatingConfig{IgnoredNameSpaces: s.Config.IgnoredNameSpaces}
	//processors.ValidationFilterChain = processors.NewValidatorChain(config)
	//
	//for _, processor := range s.Config.Validators {
	//	v := makeProcessor(processor)
	//	if v != nil {
	//		processors.ValidationFilterChain.AddValidator(v)
	//	} else {
	//		log.Errorf("invalid validator %s", processor)
	//	}
	//}
}

func initValidatingChain(config *Config) {
	vConfig := &processors.ValidatingConfig{IgnoredNameSpaces: config.IgnoredNameSpaces}
	processors.ValidationFilterChain = processors.NewValidatorChain(vConfig)

	for _, processor := range config.Validators {
		v := makeProcessor(processor)
		if v != nil {
			processors.ValidationFilterChain.AddValidator(v)
		} else {
			log.Errorf("invalid validator %s", processor)
		}
	}
}

func initMutatingChain(config *Config) {
	processors.MutatorChain = processors.NewMutatorChain()
	for _, processor := range config.Mutators {
		v := makeProcessor(processor)
		if v != nil {
			processors.MutatorChain.AddMutator(v)
		} else {
			log.Errorf("invalid mutator %s", processor)
		}
	}
}

func makeProcessor(name string) interface{} {
	r, ok := processors.ProcessorRegistry[name]
	if ok {
		var va reflect.Value
		v := reflect.New(r).Elem()
		if v.CanAddr() {
			va = v.Addr()
			// find Init function
			method := va.MethodByName("Init")
			if method.IsValid() {
				r := method.Call(nil)
				err := r[0].Interface()
				if err != nil {
					log.Errorf("init processor failed %v", err)
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
	imagevalidator.Register()
	microsegmutator.Register()
	driftprevention.Register()
}
