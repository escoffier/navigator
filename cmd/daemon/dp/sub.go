package dp

import (
	"os"
	"runtime/debug"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/image"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/scope"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/scope/image"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	imageScopeEnv string = "CIA_IMAGE_REGEXP"
)

type Subscriber struct {
	rule scope.Rule // inject scope,eg: match imageName
}

func (s *Subscriber) shouldInject(m *container.EventMessage) bool {
	if s.rule == nil {
		// not set match rule, inject all
		logging.Get().Debug().Str("containerID", m.ContainerInfo.ID).Msg("not set match rule,inject by default")
		return true
	}

	for _, v := range m.ContainerInfo.ImageRepoTags {
		match, err := s.rule.Match(scope.RuleParam{"scopeImage": v})
		if err != nil {
			logging.Get().Err(err).Msg("subscriber match image name failed,try next")
			continue
		}
		if match {
			// any image name match,inject
			logging.Get().
				Debug().
				Str("containerID", m.ContainerInfo.ID).
				Str("imageName", v).
				Msg("match rule,inject")
			return true
		} else {
			// not match,try next image name
			logging.Get().
				Debug().
				Str("containerID", m.ContainerInfo.ID).
				Str("imageName", v).
				Msg("not match rule,try next")
			continue
		}
	}

	// not match any image name,return false
	logging.Get().
		Debug().
		Str("containerID", m.ContainerInfo.ID).
		Interface("imageRepoTags", m.ContainerInfo.ImageRepoTags).
		Msg("not match any rule,not inject")
	return false
}

func (s *Subscriber) RuntimeEventCallBack(d *DriftAssurance) container.EventCallback {
	return func(message *container.EventMessage) {
		go func(m *container.EventMessage) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("runtime ev cb err: %v.stack:%s", r, debug.Stack())
				}
			}()

			logging.Get().Info().Msgf("runtime event callback event: %+v\n", m)
			if m.Event == "kill" {
				logging.Get().Info().Interface("message", m).Msg("runtime event callback stop")
				// for _, v := range m.ContainerInfo.ImageRepoTags {
				// 	d.config.DelImageUsedAndTestWhiteList(v)
				// }
				for _, v := range m.ContainerInfo.ImageDigest {
					d.config.DelImageUsedAndTestWhiteList(v)
				}
				return
			}

			if m.Event == "start" {

				if !s.shouldInject(m) {
					logging.Get().
						Info().
						Interface("imageRepoTags", m.ContainerInfo.ImageRepoTags).
						Msg("not match image rule,ignore inject")
					return
				}

				// get image whitelist
				skipScanner := false
				for _, v := range m.ContainerInfo.ImageDigest {
					if d.config.execWhiteList[v] != nil {
						skipScanner = true
						logging.Get().
							Info().
							Str("imageDigest", v).
							Msg("imageDigest in exec white list,ignore whitelist scanner")
						break
					}
				}

				if !skipScanner {
					imageInspect, err := d.rt.GetImageInspect(m.ContainerInfo.ImageID)
					if err != nil {
						logging.Get().
							Err(err).
							Str("imageID", m.ContainerInfo.ImageID).
							Msg("get image inspect failed")
					} else {
						imageInfo, err := image.MakeWhiteListByOverLay(imageInspect)
						if err != nil {
							logging.Get().
								Err(err).
								Str("imageID", m.ContainerInfo.ImageID).
								Msg("make whitelist by overlay failed")
						} else {
							for _, v := range m.ContainerInfo.ImageDigest {
								d.config.SetContainerWhiteList(v, imageInfo.WhiteList)
							}
						}
					}

				}

				// inject container by its process id
				injected, err := d.injector.DoInject(m.ContainerInfo)
				if err != nil {
					logging.Get().Err(err).Str("containedID", m.ContainerInfo.ID).Msg("inject err")
				} else {
					logging.Get().Info().Str("containedID", m.ContainerInfo.ID).Msg("inject ok")
				}
				if injected {
					for _, v := range m.ContainerInfo.ImageRepoTags {
						d.config.AddImageUsed(v)
					}
				}
			}
		}(message)
	}
}

func NewSubscriber() (*Subscriber, error) {
	s := &Subscriber{}
	matchRule := os.Getenv(imageScopeEnv)
	if len(matchRule) != 0 {
		cfg := scope.RuleConfig{
			Type: "scope-image",
			Options: scope.RuleParam{
				"regex-image-name": matchRule,
			}}
		r, err := scope.Open(cfg)
		if err != nil {
			logging.Get().Err(err).Msg("create subscriber match rule failed")
			return nil, err
		}
		s.rule = r
	}

	return s, nil
}
