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
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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
		db: rdb.GetReadDB().Session(&gorm.Session{Logger: logger.Discard}),
	}

	licenseConf, err := dal.GetConfig(context.Background(), manager.db, model.ConfLicense)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}

	if licenseConf != nil && len(licenseConf.Config) > 0 {
		if manager.currentInfo, err = manager.verifier.decode(string(licenseConf.Config)); err != nil {
			logging.Get().Error().Err(err).Msg("decode license error")
		}
	}

	return nil
}

func (licenseManager) getEnvEigenvalue() (string, error) {
	tensorCluster, err := k8s.GetTensorCluster()
	if err != nil {
		return "", err
	}

	fixedEigenvalue := strings.Join([]string{tensorCluster.Key}, "&")

	macAddrs, err := util.GetMacAddrs()
	if err != nil {
		return "", fmt.Errorf("10082")
	}

	ipAddrs, err := util.GetIPs()
	if err != nil {
		return "", fmt.Errorf("10082")
	}

	dynamicEigenvalue := strings.Join([]string{
		runtime.GOOS,
		runtime.GOARCH,
		runtime.Version(),
		os.Getenv("MY_POD_NAME"),
		strings.Join(macAddrs, ","),
		strings.Join(ipAddrs, "+"),
	}, "&")

	eigenvalue := util.MD5Hex(fixedEigenvalue) + "." + util.MD5Hex(dynamicEigenvalue)
	return eigenvalue, nil
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

	return manager.verifier.encrypt(b)
}

func RefreshLicenseInfo(licenseCode string) (err error) {
	logging.Get().Debug().Msgf("licenseCode %s", licenseCode)

	eigenvalue, err := manager.getEnvEigenvalue()
	if err != nil {
		return err
	}

	newInfo, err := manager.verifier.decode(licenseCode)
	if err != nil {
		return err
	}

	// 特殊类型的license不验证env相关信息
	if newInfo.LicenseType != "特殊(无限制)" && newInfo.Eigenvalue != eigenvalue {
		return fmt.Errorf("10081")
	}

	status := manager.verifier.validate(newInfo, false)
	if !status.StrictValid() {
		return fmt.Errorf("license invalid %v", status)
	}

	manager.currentInfo = newInfo
	return nil
}

func ValidateLicense(allowGracePeriod bool) (status Status) {
	if manager.currentInfo == nil {
		return
	}

	// 特殊类型的license不验证env相关信息
	if manager.currentInfo.LicenseType != "特殊(无限制)" {
		eigenvalue, err := manager.getEnvEigenvalue()
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			return
		}

		if strings.Split(manager.currentInfo.Eigenvalue, ".")[0] != strings.Split(eigenvalue, ".")[0] {
			logging.Get().Warn().Msg("10080")
			return
		}
	}

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
		return 0, fmt.Errorf("10083")
	}

	var (
		namespace = os.Getenv("MY_POD_NAMESPACE")
		usedNode  int64
	)

	clusterManager.TraverseClient(func(key string, cli *assets.Clientset) bool {
		daemonSetHolmesList, err := cli.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=holmes"})
		if err != nil {
			logging.Get().Warn().Err(err).Msg("get hd failed")
			return true
		}

		for _, d := range daemonSetHolmesList.Items {
			usedNode += int64(d.Status.DesiredNumberScheduled)
		}

		return true
	})

	return usedNode, nil
}
