package license

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type licenseManager struct {
	verifier    *licenseVerifier
	db          *gorm.DB
	currentInfo *Info
}

var manager *licenseManager

type envKeyInfo struct {
	Eigenvalue string `json:"eigenvalue"`
	NodeNum    int64  `json:"node_num"`
}

func loadPublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key not in pem format")
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to key file: %w", err)
	}

	return key, nil
}

func Init(rdb *databases.RDBInstance) error {
	pubk, err := loadPublicKey(publicKey)
	if err != nil {
		return err
	}

	manager = &licenseManager{
		verifier: newLicenseVerifier(licenseVerifierOption{
			publicKey:    pubk,
			remindPeriod: time.Hour * 24 * 15,
		}),
		db: rdb.GetReadDB(),
	}

	licenseConf := model.TensorConfig{}
	err = manager.db.Where("k = ?", model.ConfLicense).First(&licenseConf).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}

	if len(licenseConf.Config) > 0 {
		if manager.currentInfo, err = manager.verifier.decode(string(licenseConf.Config)); err != nil {
			logging.Get().Error().Err(err).Msg("decode license error")
		}
	}

	return nil
}

func (licenseManager) getEnvEigenvalue() (string, error) {
	macAddrs, err := util.GetMacAddrs()
	if err != nil {
		return "", err
	}

	ipAddrs, err := util.GetIPs()
	if err != nil {
		return "", err
	}

	rawEigenvalue := strings.Join([]string{
		runtime.GOOS,
		runtime.GOARCH,
		runtime.Version(),
		os.Getenv("MY_POD_NAME"),
		strings.Join(macAddrs, ","),
		strings.Join(ipAddrs, "+"),
	}, "&")

	logging.Get().Debug().Msg(rawEigenvalue)
	return util.MD5Hex(rawEigenvalue), nil
}

// GetEnvEigenvalue get environment eigenvalue
func GetEnvEigenvalue() (string, error) {
	eigenvalue, err := manager.getEnvEigenvalue()
	return eigenvalue, err
}

// GenerateEnvKey generate environment key
func GenerateEnvKey() (string, error) {
	eigenvalue, err := manager.getEnvEigenvalue()
	if err != nil {
		return "", err
	}

	nodeNum, err := GetUsedNodeNum()
	if err != nil {
		logging.Get().Error().Err(err).Msg("count nodes failed")
	}

	b, err := json.Marshal(envKeyInfo{
		Eigenvalue: eigenvalue,
		NodeNum:    nodeNum,
	})
	if err != nil {
		return "", err
	}

	logging.Get().Debug().Msgf("raw encrypt data: %s", string(b))

	return manager.verifier.encrypt(b)
}

func RefreshLicenseInfo(licenseCode string, eigenvalue string) (err error) {
	logging.Get().Debug().Msgf("licenseCode %s", licenseCode)

	newInfo, err := manager.verifier.decode(licenseCode)
	if err != nil {
		return err
	}

	logging.Get().Debug().Msgf("info: %v", newInfo)

	status := manager.verifier.validate(newInfo, false)
	if !status.StrictValid() {
		return fmt.Errorf("license invalid %v", status)
	}

	if newInfo.Eigenvalue != eigenvalue {
		return fmt.Errorf("eigenvalue not match")
	}

	manager.currentInfo = newInfo
	return nil
}

func ValidateLicense(allowGracePeriod bool) Status {
	return manager.verifier.validate(manager.currentInfo, allowGracePeriod)
}

func GetLicenseInfo() *Info {
	return manager.currentInfo
}

// GetUsedNodeNum get used node number
func GetUsedNodeNum() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return 0, fmt.Errorf("cluster manager not exist")
	}

	var (
		namespace = os.Getenv("MY_POD_NAMESPACE")
		usedNode  int64
	)

	clusterManager.TraverseClient(func(key string, cli *assets.Clientset) bool {
		daemonSetHolmesList, err := cli.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=holmes"})
		if err != nil {
			logging.Get().Warn().Err(err).Msg("get holmes daemonSet failed")
			return true
		}

		for _, d := range daemonSetHolmesList.Items {
			usedNode += int64(d.Status.DesiredNumberScheduled)
		}

		return true
	})

	return usedNode, nil
}
