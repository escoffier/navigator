package assets

import (
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"
)

type Clientset struct {
	*kubernetes.Clientset
	TensorClientset *versioned.Clientset
}

func NewForConfig(c *rest.Config) (*Clientset, error) {
	var cs Clientset
	var err error
	cs.Clientset, err = kubernetes.NewForConfig(c)
	if err != nil {
		return nil, err
	}
	cs.TensorClientset, err = versioned.NewForConfig(c)
	if err != nil {
		return nil, err
	}

	return &cs, nil
}
