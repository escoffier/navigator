package rtdetect

import (
	"bytes"
	"os"
	"strings"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
)

var (
	myNamespace = ""
)

func init() {
	myNamespace = os.Getenv("MY_POD_NAMESPACE")
}

// FIXME tmp solutions.
var watsonPodsNames = []string{
	"51c1c6", // redis+tomcat web
	"75fb1c", // ES Groovy
	"b0f328",
	"99a7ca",
	"ddc305",
	"42cca6",
	"98166d",
	"588ee1",
}

// FIXME to solve the init alerts of watson pods, filter out the corresponding events. Remove when solving watson alerts querying problems.
func isEventItemWhitelisted(data *outputs.Response, dockerInfo *nodeinfo.DockerInfoManager) bool {
	if len(data.Tags) > 0 && data.Tags[0] == "Watson" {
		return false
	}

	containerID := data.OutputFields[rtdetect.FieldContainerID]
	if _, exist := dockerInfo.FindContainerCacheData(containerID); !exist {
		return false
	}

	// filter out the events in the phase of container initialization in my pod namespace
	namespace := data.OutputFields[rtdetect.FieldK8sNsName]
	if namespace != "" && namespace == myNamespace {
		return true
	}

	podName := data.OutputFields[rtdetect.FieldK8sPodName]
	for _, prefix := range watsonPodsNames {
		if strings.Index(podName, prefix) >= 0 {
			return true
		}
	}
	return false
}

func getKeyOfPodContainerEvent(clusterKey string, data *outputs.Response) ([]byte, bool) {
	keyBui := bytes.Buffer{}
	keyBui.WriteString(clusterKey)
	keyBui.WriteRune('/')
	if data.Hostname != "" {
		keyBui.WriteString(data.Hostname)
		keyBui.WriteRune('/')
	}

	podName, exist := data.OutputFields[rtdetect.FieldK8sPodName]
	if exist && len(podName) > 0 {
		keyBui.WriteString(podName)
		keyBui.WriteRune('/')
	}

	return keyBui.Bytes(), keyBui.Len() > 0
}
