package imagetrust

import (
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1Lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"time"
)

type Controller interface {
	Start(stopCh <-chan struct{})
	//Stop()
	GetSecret(namespace, name string) (*corev1.Secret, error)
}

type controller struct {
	kubeInformerFactory informers.SharedInformerFactory
	secretLister        corev1Lister.SecretLister
	secretSynced        cache.InformerSynced
	clusterKey          string
}

func NewController(clientset *kubernetes.Clientset, clusterKey string) Controller {
	factory := informers.NewSharedInformerFactory(clientset, time.Hour*10)
	return &controller{
		kubeInformerFactory: factory,
		secretLister:        factory.Core().V1().Secrets().Lister(),
		secretSynced:        factory.Core().V1().Secrets().Informer().HasSynced,
		//stopCh:              make(chan struct{}),
	}
}

func (c *controller) Start(stopCh <-chan struct{}) {
	c.kubeInformerFactory.Start(stopCh)
	cache.WaitForCacheSync(stopCh, c.secretSynced)
	logging.GetLogger().Info().Msgf("cache has sync for cluster: %s", c.clusterKey)
}

//func (c *controller) Stop() {
//	close(c.stopCh)
//}

func (c *controller) GetSecret(namespace, name string) (*corev1.Secret, error) {
	return c.secretLister.Secrets(namespace).Get(name)
}
