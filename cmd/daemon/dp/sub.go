package dp

import (
	"encoding/json"
	"os"
	"runtime/debug"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/scope"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/scope/image"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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

func (s *Subscriber) RuntimeEventCallBack(config *ConfigManager, rt container.Runtime, wc *whitelist.WhitelistCount, injector *Injector) container.EventCallback {
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
				for _, v := range m.ContainerInfo.ImageDigest {
					if v != "" {
						continue
					}
					config.DelImageUsedAndTestWhiteList(v)
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
				if _, skipScanner = config.IsImageDigestsExist(m.ContainerInfo.ImageDigest); skipScanner {
					supportInfo, err := GetContainerPodInfo(m.ContainerInfo.PodUID, injector.npw, injector.podResInfo)
					if err != nil {
						logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
					}
					supportInfo.IsSupportDrift = true
					supportInfo.ScannerStatus = 2
					msg, err := json.Marshal(supportInfo)
					if err != nil {
						logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
					} else {
						err = Send2Kafka(injector.write, model.SubjectOfDriftSupportEvent, msg)
					}
				}

				if !skipScanner {
					imageInspect, err := rt.GetImageInspect(m.ContainerInfo.Namespace, m.ContainerInfo.ImageID)
					if err != nil {
						logging.Get().
							Err(err).
							Str("imageID", m.ContainerInfo.ImageID).
							Msg("get image inspect failed")
					} else {
						imageInfo, err := wc.GenerateExecWhiteList(imageInspect)
						if err != nil {
							logging.Get().
								Err(err).
								Str("imageID", m.ContainerInfo.ImageID).
								Msg("make whitelist by overlay failed")
						} else {

							for _, d := range m.ContainerInfo.ImageDigest {
								err = config.SetWhiteListScanning(d)
								if err != nil {
									logging.Get().Err(err).Msgf("imageDigest: %v", d)
								}
							}
							supportInfo, err := GetContainerPodInfo(m.ContainerInfo.PodUID, injector.npw, injector.podResInfo)
							if err != nil {
								logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
							}
							supportInfo.IsSupportDrift = true
							supportInfo.ScannerStatus = 1
							msg, err := json.Marshal(supportInfo)
							if err != nil {
								logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
							} else {
								err = Send2Kafka(injector.write, model.SubjectOfDriftSupportEvent, msg)
								if err != nil {
									logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
								}
							}
							if len(imageInfo.WhiteList) > 0 {
								logging.Get().
									Info().
									Str("imageID", m.ContainerInfo.ImageID).
									Interface("whiteList", imageInfo.WhiteList).
									Msg("make whitelist by overlay success")
								for _, d := range m.ContainerInfo.ImageDigest {
									config.SetContainerWhiteList(d, imageInfo.WhiteList)
									err = config.SetWhiteListReady(d)
									if err != nil {
										logging.Get().Err(err).Msgf("imageDigest: %v", d)
									}

								}
								supportInfo, err := GetContainerPodInfo(m.ContainerInfo.PodUID, injector.npw, injector.podResInfo)
								if err != nil {
									logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
								}
								supportInfo.IsSupportDrift = true
								supportInfo.ScannerStatus = 2
								msg, err := json.Marshal(supportInfo)
								if err != nil {
									logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
								} else {
									err = Send2Kafka(injector.write, model.SubjectOfDriftSupportEvent, msg)
									if err != nil {
										logging.Get().Err(err).Msgf("imageDigest: %v", m.ContainerInfo.ImageDigest)
									}
								}
							}
						}
					}

				}

				// inject container by its process id
				injected, resUUID, err := injector.DoInject(m.ContainerInfo)
				if err != nil {
					logging.Get().Err(err).Str("containedID", m.ContainerInfo.ID).Msg("inject err")
				} else {
					logging.Get().Info().Str("containedID", m.ContainerInfo.ID).Msg("inject ok")
				}
				if injected {
					for _, v := range m.ContainerInfo.ImageRepoTags {
						config.AddImageUsed(v)
					}
					policies := config.policies().Policies
					if _, ok := policies[resUUID]; ok {
						injector.EnableDriftByContainerID(m.ContainerInfo.ID)
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
