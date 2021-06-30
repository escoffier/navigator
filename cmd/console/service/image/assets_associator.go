package image

import (
	"context"
	"errors"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

type AssetsImageAssociator struct {
	postgre *rdbtools.GormWrapper
}

func NewAssetsImageAssociator(postgre *rdbtools.GormWrapper) *AssetsImageAssociator {
	return &AssetsImageAssociator{
		postgre: postgre,
	}
}
func (a *AssetsImageAssociator) BeforWatchNewCluster(ctx context.Context, clusterName string) assets.ClusterCallback {
	// for the service online count should be clear before watching to the cluster to have pods registered again.
	imageListRefCountClear(ctx, a.postgre)

	return &AssociatorClusterCB{
		parent: a,
	}
}

func (a *AssetsImageAssociator) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch: {},
	}
}

func imageListRefCountClear(ctx context.Context, postgre *rdbtools.GormWrapper) error {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := postgre.Get().WithContext(pgCtx).Model(&model.ImageList{}).Where("on_line_count > 0").Update("on_line_count", 0).Error
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "clear online count for images error")
		return err
	}
	return nil
}

func (a *AssetsImageAssociator) Name() string {
	return "images_assets_associator"
}

type AssociatorClusterCB struct {
	parent *AssetsImageAssociator
}

// getFullRepoNameTagFromContainer returns the registry location, repository name, and tag
func getTripleFromContainer(container *corev1.ContainerStatus) (string, string, string) {
	// image: 192.168.1.203:5000/tensorsec-console:latest
	repositoryTag := strings.Split(container.Image, ":")
	if len(repositoryTag) <= 1 {
		return "", "", ""
	}
	repository := strings.Join(repositoryTag[0:len(repositoryTag)-1], ":")
	tag := repositoryTag[len(repositoryTag)-1]
	pos := strings.IndexByte(repository, '/')
	if pos >= 0 && pos < len(repository)-1 {
		return repository[0:pos], repository[pos+1:], tag
	}
	return "", "", ""
}
func getImageSHAFromContainer(container *corev1.ContainerStatus) string {
	// imageID: docker-pullable://192.168.1.203:5000/tensorsec-console@sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	shaDigestAndPullInfo := strings.Split(container.ImageID, "@")
	return shaDigestAndPullInfo[len(shaDigestAndPullInfo)-1]
}

func (a *AssociatorClusterCB) imageListOnlineSet(ctx context.Context, add bool, registryLoc, fullRepoName, tags, digest string) error {
	pgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.parent.postgre.Get().WithContext(pgCtx).Transaction(func(tx *gorm.DB) error {
		var il model.ImageList
		err := tx.Model(&model.ImageList{}).Where("library = ? AND full_repo_name = ? AND tags = ?", registryLoc, fullRepoName, tags).First(&il).Error
		if err == gorm.ErrRecordNotFound { // When the image hasn't been created in the DB, try to count it with status -1
			il.Digest = digest
			il.Library = registryLoc
			il.FullRepoName = fullRepoName
			il.Tags = tags
			il.Status = -1
			if add {
				il.OnLineCount = 1
			} else {
				il.OnLineCount = -1
			}
			isErr := tx.Create(&il).Error
			return isErr
		} else if err == nil {
			if add {
				err := tx.Model(&model.ImageList{}).Where("library = ? AND full_repo_name = ? AND tags = ?", registryLoc, fullRepoName, tags).Update("on_line_count", il.OnLineCount+1).Error
				if err != nil {
					return err
				}
			} else {
				err := tx.Model(&model.ImageList{}).Where("library = ? AND full_repo_name = ? AND tags = ?", registryLoc, fullRepoName, tags).Update("on_line_count", il.OnLineCount-1).Error
				if err != nil {
					return err
				}
			}
		} else {
			return err
		}
		return nil
	})

	return nil
}

func (a *AssociatorClusterCB) OnReplicaSetEvent(newRs, oldRs *appsv1.ReplicaSet, action assets.AssetsAction) error {
	return nil
}
func (a *AssociatorClusterCB) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	if action == assets.ActionDelete {
		for _, container := range oldPod.Status.ContainerStatuses {
			imageSHA := getImageSHAFromContainer(&container)
			registryLoc, repoName, _ := getTripleFromContainer(&container)
			if len(registryLoc) == 0 || len(repoName) == 0 || len(imageSHA) == 0 {
				continue
			}
			// a.imageListOnlineSet(context.Background(), false, registryLoc, repoName, tags, imageSHA)
			// 增加镜像关联数据表
			if err := a.DeleteImageRelate(imageSHA, registryLoc, container.ContainerID); err != nil {
				logging.GetLogger().Error().Err(err).Msg("OnPodEvent delete image_relate error ")
			}

		}
	} else if action == assets.ActionAdd {
		for _, container := range newPod.Status.ContainerStatuses {
			imageSHA := getImageSHAFromContainer(&container)
			registryLoc, repoName, _ := getTripleFromContainer(&container)
			if len(registryLoc) == 0 || len(repoName) == 0 || len(imageSHA) == 0 {
				continue
			}
			// a.imageListOnlineSet(context.Background(), true, registryLoc, repoName, tags, imageSHA)
			// 增加镜像关联数据表
			if err := a.CreateImageRelate(&model.ImageRelate{Digest: imageSHA, Library: registryLoc, ContainerID: container.ContainerID}); err != nil {
				logging.GetLogger().Error().Err(err).Msg("OnPodEvent add image_relate error ")
			}
		}
	}
	return nil
}

func (a *AssociatorClusterCB) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	return nil
}

func (a *AssociatorClusterCB) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	return nil
}
func (a *AssociatorClusterCB) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	return nil
}
func (a *AssociatorClusterCB) AfterDataSynced(ctx context.Context, dataSynced bool) {

}
func (a *AssociatorClusterCB) Name() string {
	return "images_assets_associator"
}

func (a *AssociatorClusterCB) CreateImageRelate(imageRelate *model.ImageRelate) error {
	if imageRelate == nil {
		return nil
	}
	if imageRelate.Digest == "" || imageRelate.Library == "" {
		return errors.New("ImageRelate no digest or no library")
	}
	pgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !strings.Contains(imageRelate.Library, "http") {
		imageRelate.Library = "https://" + imageRelate.Library
	}

	err := a.parent.postgre.Get().WithContext(pgCtx).Create(imageRelate).Error
	return err
}
func (a *AssociatorClusterCB) DeleteImageRelate(digest, library, containerId string) error {
	if digest == "" || library == "" {
		return errors.New("no digest or no library")
	}
	pgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !strings.Contains(library, "http") {
		library = "https://" + library
	}
	err := a.parent.postgre.Get().WithContext(pgCtx).Where("digest = ? AND library = ? AND container_id = ?", digest, library, containerId).Delete(&model.ImageRelate{}).Error
	return err
}
