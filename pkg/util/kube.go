package util

import (
	"regexp"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

func GetOwnerOfPod(pod *corev1.Pod) (name string, kind string) {
	var ownerName, ownerKind string
	owner := metav1.GetControllerOf(pod)
	if owner != nil {
		logging.Get().Info().Msgf("owner kind: %s", owner.Kind)
		if owner.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] != "" && strings.HasSuffix(owner.Name, pod.Labels["pod-template-hash"]) {
			name := strings.TrimSuffix(owner.Name, "-"+pod.Labels["pod-template-hash"])
			ownerKind = "Deployment"
			ownerName = name
		} else if owner.Kind == "Job" {
			// If job name suffixed with `-<digit-timestamp>`, where the length of digit timestamp is 8~10,
			// trim the suffix and set kind to cron job.
			if jn := cronJobNameRegexp.FindStringSubmatch(owner.Name); len(jn) == 2 {
				owner.Name = jn[1]
				owner.Kind = "CronJob"
				// heuristically set cron job api version to v1beta1 as it cannot be derived from pod metadata.
				// Cronjob is not GA yet and latest version is v1beta1: https://github.com/kubernetes/enhancements/pull/978
			}
		}
	} else {
		ownerKind = "Pod"
		ownerName = pod.Name
	}

	return ownerName, ownerKind
}
