package immune

import (
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type PolicyView struct {
	*model.ImmunePolicy

	RelatedResource *Resource           `json:"relatedResource"`
	Profiles        []*ContainerProfile `json:"profiles,omitempty"`

	ProfilesChanges *ProfilesChanges `json:"profilesChanges,omitempty"`
}

type ProfilesChanges struct {
	Add    []*ContainerProfile `json:"add"`
	Delete []*ContainerProfile `json:"delete"`
}

type ContainerProfile struct {
	ContainerName string `json:"containerName"`
	Configuration string `json:"configuration"`
}

type ContainerInfo struct {
	ContainerName string `json:"containerName"`
	ImageID       string `json:"imageID"`
}

type Resource struct {
	Name       string           `json:"name"`
	Kind       string           `json:"kind"`
	Namespace  string           `json:"namespace"`
	ClusterKey string           `json:"clusterKey"`
	Containers []*ContainerInfo `json:"containers"`
}

func getModelsFromProfile(cprof *ContainerProfile, policy *model.ImmunePolicy, now time.Time, creator string) ([]*model.ImmuneProfile, error) {
	profiles := make([]*model.ImmuneProfile, 0, 50)
	switch policy.Kind {
	case model.PolicyKindSyscalls:
		var conf model.SyscallsConfigurations
		err := json.Unmarshal([]byte(cprof.Configuration), &conf)
		if err != nil {
			return nil, err
		}
		for _, profile := range conf {
			iprof := new(model.ImmuneProfile)
			iprof.ContainerName = cprof.ContainerName
			iprof.PolicyID = policy.ID
			iprof.Value = []byte(profile)
			iprof.CreatedAt = now
			iprof.Creator = creator
			profiles = append(profiles, iprof)
		}
	case model.PolicyKindFileRW:
		var conf model.FileRWConfigurations
		err := json.Unmarshal([]byte(cprof.Configuration), &conf)
		if err != nil {
			return nil, err
		}
		for _, profile := range conf {
			valBytes, err := json.Marshal(profile)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("marshal profile error. v: %+v", profile)
				continue
			}
			iprof := new(model.ImmuneProfile)
			iprof.ContainerName = cprof.ContainerName
			iprof.PolicyID = policy.ID
			iprof.Value = valBytes
			iprof.CreatedAt = now
			profiles = append(profiles, iprof)
		}
	case model.PolicyKindCmdExec:
		var conf model.CmdLineExecConfigurations
		err := json.Unmarshal([]byte(cprof.Configuration), &conf)
		if err != nil {
			return nil, err
		}
		for _, profile := range conf {
			valBytes, err := json.Marshal(profile)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("marshal profile error. v: %+v", profile)
				continue
			}
			iprof := new(model.ImmuneProfile)
			iprof.ContainerName = cprof.ContainerName
			iprof.PolicyID = policy.ID
			iprof.Value = valBytes
			iprof.CreatedAt = now
			profiles = append(profiles, iprof)
		}
	default:
		return nil, nil
	}
	return profiles, nil
}
