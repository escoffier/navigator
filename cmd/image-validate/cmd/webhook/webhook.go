package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/image-validate/pkg/fileters"
	"gitlab.com/piccolo_su/vegeta/cmd/image-validate/pkg/validator"
	"io/ioutil"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"net/http"
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
	ws.initFilterChain()
	return ws, nil
}

func (s *webHookServer) Start() {
	log.Debug("starting server ")
	err := s.Server.ListenAndServeTLS("", "")
	if err != nil {
		log.Errorf("failed to start server: %v", err)
		return
	}
}

func (s *webHookServer) Stop() {
	s.Server.Shutdown(context.Background())
}
func (s *webHookServer) Mutating(w http.ResponseWriter, r *http.Request) {

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
	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}
	review, _ := json.MarshalIndent(&ar, "", "  ")
	fmt.Println(string(review))

	kind := ar.Request.Kind.Kind

	validateParas := fileters.ValidatingParameters{
		Namespace: ar.Request.Namespace,
		Kind:      kind,
	}
	err = fileters.ValidationFilterChain.Validate(validateParas, ar.Request.Object.Raw)
	if err != nil {
		log.Errorf("process err %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	admissionReview := v1beta1.AdmissionReview{}
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

func (s *webHookServer) initFilterChain() {
	config := &fileters.ValidatingConfig{IgnoredNameSpaces: s.Config.IgnoredNameSpaces}
	fileters.ValidationFilterChain = fileters.NewFilterChain(config)
	fileters.ValidationFilterChain.AddPodFilter(validator.NewPodValidator(s.Config.ImageValidateServer))
}
