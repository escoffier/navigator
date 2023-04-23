package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/avast/retry-go"
	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	appsv1 "k8s.io/api/apps/v1"
	batchV1 "k8s.io/api/batch/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetImagePrefixAndPostFixFrom returns prefix, image name, tag, ok. harbor.cn/abc/service:latest returns harbor.cn/abc /service latest
func GetImagePrefixAndPostFixFrom(image string) (string, string, string, bool) {
	if len(image) == 0 {
		return "", "", "", false
	}
	tagPos := strings.LastIndexByte(image, ':')
	if tagPos <= 0 {
		return "", "", "", false
	}
	fullRepoName := image[:tagPos]
	fullRepoPos := strings.LastIndexByte(fullRepoName, '/')
	if fullRepoPos <= 0 {
		return "", "", "", false
	}
	return image[:fullRepoPos], image[fullRepoPos:tagPos], image[tagPos+1:], true
}

func getClusterManagerdeploymenetObj(ctx context.Context, kubeClient *pkgassets.Clientset, myResourcePrefix, myNamespace string) (*appsv1.Deployment, error) {
	clusterManagerName := fmt.Sprintf("%s-cluster-manager", myResourcePrefix)
	var res *appsv1.Deployment
	var notFound bool
	err := util.RetryWithBackoff(ctx, func() error {
		var oneErr error
		res, oneErr = kubeClient.AppsV1().Deployments(myNamespace).Get(ctx, clusterManagerName, metav1.GetOptions{})
		if k8serrors.IsNotFound(oneErr) {
			notFound = true
			return nil
		} else if oneErr != nil {
			return oneErr
		}
		return nil
	}, retry.Attempts(3))
	if err != nil {
		return nil, err
	}
	if notFound || res == nil {
		return nil, fmt.Errorf("target resource %s/%s not found", myNamespace, clusterManagerName)
	}
	return res, nil
}

func GetProductVersionFrom(ctx context.Context, kubeClient *pkgassets.Clientset, myResourcePrefix, myNamespace string) (string, error) {
	res, err := getClusterManagerdeploymenetObj(ctx, kubeClient, myResourcePrefix, myNamespace)
	if err != nil {
		return "", err
	}

	for _, cont := range res.Spec.Template.Spec.Containers {
		if len(cont.Image) > 0 {
			pos := strings.LastIndexByte(cont.Image, ':')
			if pos > 0 && pos < len(cont.Image)-1 {
				return cont.Image[pos+1:], nil
			}
		}
	}
	return "", fmt.Errorf("target resource image prefix %s/cluster-manager not found", myNamespace)
}
func GetTargetClusterImageSplitInfo(ctx context.Context, kubeClient *pkgassets.Clientset, myResourcePrefix, myNamespace string) (string, string, error) {
	res, err := getClusterManagerdeploymenetObj(ctx, kubeClient, myResourcePrefix, myNamespace)
	if err != nil {
		return "", "", err
	}

	for _, cont := range res.Spec.Template.Spec.Containers {
		repoLoc, fullRepoName, tag, ok := GetImagePrefixAndPostFixFrom(cont.Image)
		if ok && repoLoc != "" && fullRepoName != "" {
			return repoLoc, tag, nil
		}
	}
	return "", "", fmt.Errorf("target resource image prefix %s/cluster-manager not found", myNamespace)
}

// ReplaceJobYamlWithTheTargetImageRepos : for sub clusters, the image repos might be different from the yamls which is defined by the image repositories of the main cluster; so get the image repo prefix dynamically.
func ReplaceJobYamlWithTheTargetImageRepos(ctx context.Context, job *batchV1.Job, kubeClient *pkgassets.Clientset, myResourcePrefix, myNamespace string) (string, string, error) {
	targetRepoURL, targetTag, err := GetTargetClusterImageSplitInfo(ctx, kubeClient, myResourcePrefix, myNamespace)
	if err != nil {
		logging.Get().Err(err).Msg("get image repo error")
	} else {
		for i := range job.Spec.Template.Spec.Containers {
			_, fullRepoName, _, ok := GetImagePrefixAndPostFixFrom(job.Spec.Template.Spec.Containers[i].Image)
			if ok && len(fullRepoName) > 0 {
				job.Spec.Template.Spec.Containers[i].Image = targetRepoURL + fullRepoName + ":" + targetTag
				logging.Get().Debug().Str("image", job.Spec.Template.Spec.Containers[i].Image).Msg("right job image")
			}
		}
		for i := range job.Spec.Template.Spec.InitContainers {
			_, fullRepoName, _, ok := GetImagePrefixAndPostFixFrom(job.Spec.Template.Spec.InitContainers[i].Image)
			if ok && len(fullRepoName) > 0 {
				job.Spec.Template.Spec.InitContainers[i].Image = targetRepoURL + fullRepoName + ":" + targetTag
				logging.Get().Debug().Str("image", job.Spec.Template.Spec.InitContainers[i].Image).Msg("right job image")
			}
		}
	}
	return targetRepoURL, targetTag, err
}
