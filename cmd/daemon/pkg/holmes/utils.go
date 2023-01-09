package holmes

import (
	"bytes"
	"os"
	"strings"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	myNamespace = ""
	myNodeName  = ""
)

func init() {
	myNamespace = os.Getenv("MY_POD_NAMESPACE")
	myNodeName = os.Getenv("MY_NODE_NAME")
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
func isEventItemWhitelisted(data *outputs.Response, containerInfo nodeinfo.ContainerInfoManager) bool {
	containerID := data.OutputFields[model.FieldContainerID]
	if _, exist := containerInfo.FindContainerCacheData(containerID); !exist {
		return false
	}

	// filter out the events in the phase of container initialization in my pod namespace
	namespace := data.OutputFields[model.FieldK8sNsName]
	if namespace != "" && namespace == myNamespace {
		return true
	}

	podName := data.OutputFields[model.FieldK8sPodName]
	for _, prefix := range watsonPodsNames {
		if strings.Index(podName, prefix) >= 0 {
			return true
		}
	}

	return false
}

func GetKeyOfSignal(clusterKey string) ([]byte, bool) {
	keyBui := bytes.Buffer{}
	keyBui.WriteString(myNodeName)
	keyBui.WriteRune('/')
	keyBui.WriteString(clusterKey)

	return keyBui.Bytes(), keyBui.Len() > 0
}
