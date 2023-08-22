package immune

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/avast/retry-go"
	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	instance *Service
	once     sync.Once
)

func Init(rdb *databases.RDBInstance) error {
	once.Do(func() {
		instance = newService(rdb)
	})
	return nil
}
func Get() (*Service, bool) {
	return instance, instance != nil
}

type Service struct {
	rdb         *databases.RDBInstance
	taskManager *TaskManager
}

func newService(rdb *databases.RDBInstance) *Service {
	taskManager := newTaskManager(rdb)
	return &Service{
		rdb:         rdb,
		taskManager: taskManager,
	}
}

func (s *Service) ListPolicies(ctx context.Context, queryOpt *dal.ImmunePoliciesQueryOption, offset, limit int) ([]*PolicyView, int64, error) {
	policies, err := dal.ListImmunePolicies(ctx, s.rdb.Get(), queryOpt, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	IDs := make([]uint32, 0, len(policies))
	for _, p := range policies {
		IDs = append(IDs, p.ResourceUUID)
	}

	resources, err := dal.GetResources(ctx, s.rdb.Get(), dal.ResourcesQuery().WithInConditionCustom("id", IDs), 0, len(IDs))
	if err != nil {
		return nil, 0, err
	}
	policyViews := make([]*PolicyView, 0, len(policies))
	for _, p := range policies {
		pview := new(PolicyView)
		pview.ImmunePolicy = p
		pview.RelatedResource = new(Resource)

		for _, res := range resources {
			if res.ID == pview.ResourceUUID {
				pview.RelatedResource.ClusterKey = res.ClusterKey
				pview.RelatedResource.Kind = res.Kind
				pview.RelatedResource.Namespace = res.Namespace
				pview.RelatedResource.Name = res.Name
			}
		}
		policyViews = append(policyViews, pview)
	}

	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var totalCount int64
	err = util.RetryWithBackoff(tctx, func() error {
		var oneErr error
		totalCount, oneErr = dal.CountImmunePolicies(ctx, s.rdb.Get(), queryOpt)
		return oneErr
	})
	if err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "count immune polices error. query: %+v", queryOpt)
		return policyViews, int64(len(policies)), nil
	}
	return policyViews, totalCount, nil
}

func (s *Service) fetchResource(ctx context.Context, policy *model.ImmunePolicy) (*Resource, error) {
	var resources []*model.TensorResource
	err := util.RetryWithBackoff(ctx, func() error {
		var err error
		resources, err = dal.GetResources(ctx, s.rdb.Get(), dal.ResourcesQuery().WithID(policy.ResourceUUID), 0, 1)
		return err
	}, retry.Attempts(2))
	if err != nil {
		return nil, err
	} else if len(resources) == 0 {
		return nil, errors.New("not found")
	} else {
		resView := new(Resource)
		resView.ClusterKey = resources[0].ClusterKey
		resView.Kind = resources[0].Kind
		resView.Name = resources[0].Name
		resView.Namespace = resources[0].Namespace
		if resources[0].PodTemplate != nil {
			resView.Containers = make([]*ContainerInfo, len(resources[0].PodTemplate.Containers))
			for i := range resources[0].PodTemplate.Containers {
				resView.Containers[i] = new(ContainerInfo)
				resView.Containers[i].ContainerName = resources[0].PodTemplate.Containers[i].Name
				resView.Containers[i].ImageID = resources[0].PodTemplate.Containers[i].Image
			}
		}
		return resView, nil
	}
}

func (s *Service) fetchProfiles(ctx context.Context, policy *model.ImmunePolicy) ([]*ContainerProfile, error) {
	var profiles []*model.ImmuneProfile
	err := util.RetryWithBackoff(ctx, func() error {
		var err error
		profiles, err = dal.GetProfilesOfPolicy(ctx, s.rdb.Get(), policy.ID, "")
		return err
	}, retry.Attempts(2))

	if err != nil {
		return nil, err
	} else {
		switch policy.Kind {
		case model.PolicyKindSyscalls:
			contMap := make(map[string]model.SyscallsConfigurations, 5)
			for _, p := range profiles {
				syscallConfs, exist := contMap[p.ContainerName]
				if !exist {
					syscallConfs = make(model.SyscallsConfigurations, 0, len(profiles))
				}
				syscallConfs = append(syscallConfs, string(p.Value))
				contMap[p.ContainerName] = syscallConfs
			}
			profiles := make([]*ContainerProfile, 0, len(contMap))
			for containerName, syscallConfs := range contMap {
				cprof := new(ContainerProfile)
				cprof.ContainerName = containerName
				bytes, err := json.Marshal(syscallConfs)
				if err != nil {
					logging.Get().Err(err).Msgf("marshal syscall confs error. containerName: %s data: %+v", containerName, syscallConfs)
					continue
				}
				cprof.Configuration = string(bytes)
				profiles = append(profiles, cprof)
			}
			return profiles, nil
		case model.PolicyKindFileRW:
			contMap := make(map[string]model.FileRWConfigurations, 5)
			for _, p := range profiles {
				rwConfs, exist := contMap[p.ContainerName]
				if !exist {
					rwConfs = make(model.FileRWConfigurations, 0, len(profiles))
				}
				var elem model.FRWElement
				err := json.Unmarshal(p.Value, &elem)
				if err != nil {
					logging.Get().Err(err).Msgf("unmarshal fileRW confs error. data: %s. profile: %+v", string(p.Value), p)
					continue
				}
				rwConfs = append(rwConfs, elem)
				contMap[p.ContainerName] = rwConfs
			}
			profiles := make([]*ContainerProfile, 0, len(contMap))
			for containerName, fileRWConfs := range contMap {
				cprof := new(ContainerProfile)
				cprof.ContainerName = containerName
				bytes, err := json.Marshal(fileRWConfs)
				if err != nil {
					logging.Get().Err(err).Msgf("marshal PolicyKindFileRW confs error. containerName: %s data: %+v", containerName, fileRWConfs)
					continue
				}
				cprof.Configuration = string(bytes)
				profiles = append(profiles, cprof)
			}
			return profiles, nil
		case model.PolicyKindBinaryExec:
			return make([]*ContainerProfile, 0), nil
		case model.PolicyKindCmdExec:
			contMap := make(map[string]model.CmdLineExecConfigurations, 5)
			for _, p := range profiles {
				cmdConfs, exist := contMap[p.ContainerName]
				if !exist {
					cmdConfs = make(model.CmdLineExecConfigurations, 0, len(profiles))
				}
				var elem model.CmdExecElement
				err := json.Unmarshal(p.Value, &elem)
				if err != nil {
					logging.Get().Err(err).Msgf("unmarshal fileRW confs error. data: %s. profile: %+v", string(p.Value), p)
					continue
				}
				cmdConfs = append(cmdConfs, elem)
				contMap[p.ContainerName] = cmdConfs
			}
			profiles := make([]*ContainerProfile, 0, len(contMap))
			for containerName, cmdConfs := range contMap {
				cprof := new(ContainerProfile)
				cprof.ContainerName = containerName
				bytes, err := json.Marshal(cmdConfs)
				if err != nil {
					logging.Get().Err(err).Msgf("marshal PolicyKindCmdExec confs error. containerName: %s data: %+v", containerName, cmdConfs)
					continue
				}
				cprof.Configuration = string(bytes)
				profiles = append(profiles, cprof)
			}
			return profiles, nil
		default:
			return nil, fmt.Errorf("error policy kind %d", policy.Kind)
		}
	}
}
func (s *Service) GetPolicy(ctx context.Context, policyID int64) (*PolicyView, error) {
	pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var policy *model.ImmunePolicy
	err := util.RetryWithBackoff(pctx, func() error {
		var err error
		policy, err = dal.GetPolicy(ctx, s.rdb.Get(), policyID)
		if err == gorm.ErrRecordNotFound {
			return nil
		}
		return err
	}, retry.Attempts(2))
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, gorm.ErrRecordNotFound
	}

	pview := new(PolicyView)
	pview.ImmunePolicy = policy

	// concurrent fetch data
	resourceChan := make(chan interface{})
	profilesChan := make(chan interface{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().WithContext(ctx).Errorf(nil, "Panic when fetching policy's resource: %v. stack: %s", r, debug.Stack())
				resourceChan <- errors.New("panic")
			}
		}()
		resView, err := s.fetchResource(ctx, policy)
		if err != nil {
			resourceChan <- err
		} else {
			resourceChan <- resView
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().WithContext(ctx).Errorf(nil, "Panic when fetching policy's profiles: %v. stack: %s", r, debug.Stack())
				profilesChan <- errors.New("panic")
			}
		}()

		profiles, err := s.fetchProfiles(ctx, policy)
		if err != nil {
			profilesChan <- err
		} else {
			profilesChan <- profiles
		}
	}()

	resourceObj := <-resourceChan
	switch val := resourceObj.(type) {
	case error:
		logging.Get().WithContext(ctx).Errorf(val, "fetch resources error for policy %+v", pview)
		return nil, val
	case *Resource:
		pview.RelatedResource = val
	default:
		logging.Get().WithContext(ctx).Errorf(nil, "fetch resources return invalid value %v for policy %+v", val, pview)
		return nil, errors.New("invalid result")
	}

	profilesObj := <-profilesChan
	switch val := profilesObj.(type) {
	case error:
		logging.Get().WithContext(ctx).Errorf(val, "fetch profiles error for policy %+v", pview)
		return nil, val
	case []*ContainerProfile:
		pview.Profiles = val
	default:
		logging.Get().WithContext(ctx).Errorf(nil, "fetch profiles return invalid value %v for policy %+v", val, pview)
		return nil, errors.New("invalid result")
	}

	return pview, nil
}

func (s *Service) AddPolicy(ctx context.Context, policy *PolicyView) (int64, error) {
	if policy == nil {
		return 0, errors.New("nil policy")
	}

	now := time.Now()
	userName := request.GetUsernameFromContext(ctx)
	policyModel := policy.ImmunePolicy
	policyModel.Creator = userName
	policyModel.Updater = userName
	policyModel.UpdatedAt = now
	policyModel.CreatedAt = now

	if policy.RelatedResource == nil || policy.RelatedResource.ClusterKey == "" || policy.RelatedResource.Namespace == "" || policy.RelatedResource.Kind == "" || policy.RelatedResource.Name == "" {
		return 0, errors.New("lack of resource")
	}
	policyModel.ResourceUUID = dal.GetResourceUUID(policy.RelatedResource.ClusterKey, policy.RelatedResource.Namespace, policy.RelatedResource.Kind, policy.RelatedResource.Name)
	policyModel.ClusterKey = policy.RelatedResource.ClusterKey
	err := s.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		policyModel, err = dal.CreateImmunePolicy(ctx, tx, policyModel)
		if err != nil {
			return err
		}

		profiles := make([]*model.ImmuneProfile, 0, 50)
		for _, profile := range policy.Profiles {
			profileModels, err := getModelsFromProfile(profile, policyModel, now, userName)
			if err != nil {
				logging.Get().Err(err).Msgf("get model from profile error. profile: %+v", profile)
				continue
			}
			profiles = append(profiles, profileModels...)
		}

		for _, profileModel := range profiles {
			err := util.RetryWithBackoff(ctx, func() error {
				_, err := dal.CreateImmuneProfile(ctx, tx, profileModel)
				return err
			}, retry.Attempts(3))
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		logging.Get().Err(err).Msg("createImmuneProfile submit policy and profiles error")
		return 0, err
	}

	return policyModel.ID, nil
}

func (s *Service) EditPolicy(ctx context.Context, policyID int64, policyView *PolicyView, readStamp int64) error {
	// temporarily ignore stamp version check

	now := time.Now()
	userName := request.GetUsernameFromContext(ctx)
	policy := policyView.ImmunePolicy
	policy.Updater = userName
	policy.UpdatedAt = now

	err := s.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var upErr error
		reErr := util.RetryWithBackoff(ctx, func() error {

			uperr := dal.UpdateImmunePolicy(ctx, tx, policy.ID, policy)
			if uperr == gorm.ErrRecordNotFound {
				upErr = uperr
				return nil
			}
			return uperr
		}, retry.Attempts(3))
		if reErr != nil {
			return reErr
		}
		if upErr != nil {
			return upErr
		}

		var newPolicy *model.ImmunePolicy
		err := util.RetryWithBackoff(ctx, func() error {
			var err error
			newPolicy, err = dal.GetImmunePolicy(ctx, tx, policyID)
			return err
		})

		if err != nil {
			return err
		}

		if policyView.ProfilesChanges != nil {
			toAddModels := make(map[int64]*model.ImmuneProfile, len(policyView.ProfilesChanges.Add))
			toDelModels := make(map[int64]*model.ImmuneProfile, len(policyView.ProfilesChanges.Delete))
			for _, toAdd := range policyView.ProfilesChanges.Add {
				profiles, err := getModelsFromProfile(toAdd, newPolicy, now, userName)
				if err != nil {
					logging.Get().WithContext(ctx).Errorf(err, "getModelsFromProfile error. data: %+v", toAdd)
					continue
				}
				for _, profile := range profiles {
					profile.UUID = dal.GetUUIDOfProfile(profile)
					toAddModels[profile.UUID] = profile
				}

			}
			for _, toDelete := range policyView.ProfilesChanges.Delete {
				profiles, err := getModelsFromProfile(toDelete, newPolicy, now, userName)
				if err != nil {
					logging.Get().WithContext(ctx).Errorf(err, "getModelsFromProfile error. data: %+v", toDelete)
					continue
				}
				for _, profile := range profiles {
					profile.UUID = dal.GetUUIDOfProfile(profile)
					toDelModels[profile.UUID] = profile
				}
			}

			toDelArr := make([]*model.ImmuneProfile, 0, len(toDelModels))
			for _, p := range toDelModels {
				if _, exist := toAddModels[p.UUID]; !exist {
					toDelArr = append(toDelArr, p)
				}
			}
			toAddArr := make([]*model.ImmuneProfile, 0, len(toAddModels))
			for _, p := range toAddModels {
				if _, exist := toDelModels[p.UUID]; !exist {
					toAddArr = append(toAddArr, p)
				}
			}
			for _, model := range toDelArr {
				err := util.RetryWithBackoff(ctx, func() error {
					return dal.DeleteImmuneProfile(ctx, tx, model)
				}, retry.Attempts(3))
				if err != nil {
					return err
				}
			}
			for _, model := range toAddArr {
				err := util.RetryWithBackoff(ctx, func() error {
					_, err := dal.CreateImmuneProfile(ctx, tx, model)
					return err
				}, retry.Attempts(3))
				if err != nil {
					return err
				}
			}

		}
		return nil
	})
	if err != nil {
		logging.Get().Err(err).Msg("editImmuneProfile submit policy and profiles error")
		return err
	}
	return nil
}

func (s *Service) PolicyStatusAction(ctx context.Context, action model.PolicyStatus, policyID, readStamp int64) error {
	// TODO temporarily ignore stamp check

	// TODO distribute policies
	var nfErr error
	err := util.RetryWithBackoff(ctx, func() error {
		err := dal.SetImmunePolicyStatus(ctx, s.rdb.Get(), policyID, action)
		if err == gorm.ErrRecordNotFound {
			nfErr = err
			return nil
		}
		return err
	}, retry.Attempts(3))
	if nfErr != nil {
		return nfErr
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) CheckTaskState(ctx context.Context, resourceUUID uint32) (model.TaskState, error) {
	query := dal.NewImmuneTasksQuery().WithResourceUUID(resourceUUID)
	tasks, err := dal.GetImmuneTasks(ctx, s.rdb.Get(), query, 0, 4)
	if err != nil {
		return 0, err
	}

	state := model.TStateNoLearning
	for _, t := range tasks {
		if t.State == model.TStateLearning || t.State == model.TStatePending {
			return t.State, nil
		}
		if t.State == model.TStateLearned {
			state = t.State
		}
	}
	return state, nil
}

func (s *Service) StartTask(ctx context.Context, resourceUUID uint32, policyKind model.PolicyKind, ttl time.Duration) (int64, error) {
	now := time.Now()
	userName := request.GetUsernameFromContext(ctx)

	t := new(model.ImmuneTask)
	t.ResourceUUID = resourceUUID
	t.PolicyKind = policyKind
	t.State = model.TStateLearning // TODO mock state
	t.CreatedAt = now
	t.Creator = userName
	t.TerminatedAt = now.Add(ttl)
	t.Status = 0

	var taskID int64
	err := s.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// TODO start real jobs to learn

		var err error
		taskID, err = dal.CreateImmuneTask(ctx, tx, t)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return taskID, nil
}

func (s *Service) fromResourceToView(ctx context.Context, res *model.TensorResource) *Resource {
	r := new(Resource)
	r.UUID = res.ID
	r.Namespace = res.Namespace
	r.Name = res.Name
	r.Kind = res.Kind
	r.ClusterKey = res.ClusterKey
	if res.PodTemplate != nil {
		r.Containers = make([]*ContainerInfo, len(res.PodTemplate.Containers))
		for i, c := range res.PodTemplate.Containers {
			r.Containers[i] = new(ContainerInfo)
			r.Containers[i].ContainerName = c.Name
			r.Containers[i].ImageID = c.Image
		}
	}

	var err error
	r.State, err = s.CheckTaskState(ctx, res.ID)
	if err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "check task state error for resource: %+v", r)
		r.State = model.TStateNoLearning
	}
	r.PoliciesNum, err = dal.CountImmunePolicies(ctx, s.rdb.Get(), dal.NewImmunePoliciesQuery().WithResourceUUID(r.UUID))
	if err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "get policies num error for resource: %+v", r)
		r.PoliciesNum = 0
	}
	return r
}
func (s *Service) GetResources(ctx context.Context, query *dal.ResourcesQueryOption, offset, limit int) ([]*Resource, int64, error) {
	resources, err := dal.GetResources(ctx, s.rdb.Get(), query, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	var totalCnt int64
	err = util.RetryWithBackoff(ctx, func() error {
		var err error
		totalCnt, err = dal.CountResources(ctx, s.rdb.Get(), query)
		return err
	}, retry.Attempts(3))
	if err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "count resources error. query: %+v", query)
		totalCnt = int64(limit)
	}

	resViews := make([]*Resource, len(resources))
	for i, res := range resources {
		resViews[i] = s.fromResourceToView(ctx, res)
	}
	return resViews, totalCnt, nil
}
