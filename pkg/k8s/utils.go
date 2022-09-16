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

func GetImagePrefixAndPostFixFrom(image string) (string, string, bool) {
	if len(image) == 0 {
		return "", "", false
	}
	pos := strings.LastIndexByte(image, ':')
	if pos <= 0 {
		return "", "", false
	}
	fullRepoName := image[:pos]
	pos = strings.LastIndexByte(fullRepoName, '/')
	if pos <= 0 {
		return "", "", false
	}
	return image[:pos+1], image[pos+1:], true
}

func GetImageRepositoryAndProjectPrefix(ctx context.Context, kubeClient *pkgassets.Clientset, myResourcePrefix, myNamespace string) (string, error) {
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
		return "", err
	}
	if notFound || res == nil {
		return "", fmt.Errorf("target resource %s/%s not found", myNamespace, clusterManagerName)
	}

	for _, cont := range res.Spec.Template.Spec.Containers {
		prefix, _, ok := GetImagePrefixAndPostFixFrom(cont.Image)
		if ok && prefix != "" {
			return prefix, nil
		}
	}
	return "", fmt.Errorf("target resource image prefix %s/%s not found", myNamespace, clusterManagerName)
}

// ReplaceJobYamlWithTheTargetImageRepos : for sub clusters, the image repos might be different from the yamls which is defined by the image repositories of the main cluster; so get the image repo prefix dynamically.
func ReplaceJobYamlWithTheTargetImageRepos(ctx context.Context, job *batchV1.Job, kubeClient *pkgassets.Clientset, myResourcePrefix, myNamespace string) {
	imagePrefix, err := GetImageRepositoryAndProjectPrefix(ctx, kubeClient, myResourcePrefix, myNamespace)
	if err != nil {
		logging.Get().Err(err).Msg("get image repo error")
	} else {
		for i := range job.Spec.Template.Spec.Containers {
			_, postfix, ok := GetImagePrefixAndPostFixFrom(job.Spec.Template.Spec.Containers[i].Image)
			if ok && len(postfix) > 0 {
				job.Spec.Template.Spec.Containers[i].Image = imagePrefix + postfix
				logging.Get().Debug().Str("image", job.Spec.Template.Spec.Containers[i].Image).Msg("right job image")
			}
		}
		for i := range job.Spec.Template.Spec.InitContainers {
			_, postfix, ok := GetImagePrefixAndPostFixFrom(job.Spec.Template.Spec.InitContainers[i].Image)
			if ok && len(postfix) > 0 {
				job.Spec.Template.Spec.InitContainers[i].Image = imagePrefix + postfix
				logging.Get().Debug().Str("image", job.Spec.Template.Spec.InitContainers[i].Image).Msg("right job image")
			}
		}
	}
}
