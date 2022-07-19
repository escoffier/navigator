package degrade

import (
	"os"
	"runtime/debug"
	"strings"

	"gitlab.com/security-rd/go-pkg/cmap"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
)

type degAction uint8

const (
	DegradeActionDegrade = degAction(0)
	DegradeActionRecover = degAction(1)
)

var (
	myNodeName = ""
	inputChan  chan degAction
)

func init() {
	myNodeName = os.Getenv("MY_NODE_NAME")
	inputChan = make(chan degAction, 3)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("degrade watcher panic: %v", r)
			}
		}()

		for act := range inputChan {
			switch act {
			case DegradeActionRecover:
				driftRecover()
			case DegradeActionDegrade:
				driftDegrade()
			default:
				logging.Get().Warn().Uint8("action", uint8(act)).Msg("invalid action")
			}
		}
	}()
}

func DegradationCmapWatcher(oldCm, newCm *corev1.ConfigMap, action cmap.Action) error {
	switch action {
	case cmap.ActionDelete:
		inputChan <- DegradeActionRecover
	case cmap.ActionAdd, cmap.ActionUpdate:
		value, exist := newCm.Data["driftDefense"]
		if !exist || value == "" {
			inputChan <- DegradeActionRecover
		} else if value == "*" || (len(myNodeName) > 0 && strings.Index(value, myNodeName) >= 0) {
			inputChan <- DegradeActionDegrade
		} else {
			inputChan <- DegradeActionRecover
		}

	}
	return nil
}
