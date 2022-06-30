// Package registry defines the  models and a common interface for
// registry implementations.
package registry

import (
	"context"
	"errors"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// RegistrableComponentConfig is a configuration block that can be used to
// determine which registrable component should be initialized and pass custom
// configuration to it.
type RegistrableComponentConfig struct {
	Type    string
	Options map[string]interface{}
}

var drivers = make(map[string]Driver)
var DriverTypes = make([]string, 0)

// Driver is a function that connects a registry specified by its client driver type and specific
// configuration.
type Driver func(RegistrableComponentConfig) (Registry, error)

// ImageListExtender is a function that can do some stuff when sync one image
type ImageListExtender func(ctx context.Context, image Image) (*ListImagesRes, error)
type CreateOrAddRetryCountExtender func(ctx context.Context, image Image) error
type DeleteImageRetryExtender func(ctx context.Context, image Image) error

// Register makes a Constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) error {
	if driver == nil {
		return errors.New("could not register nil Driver")
	}
	if _, dup := drivers[name]; dup {
		return errors.New("could not register duplicate Driver: " + name)
	}
	drivers[name] = driver
	DriverTypes = append(DriverTypes, name)
	return nil
}

// Open opens a registry specified by a configuration.
func Open(cfg RegistrableComponentConfig) (Registry, error) {
	driver, ok := drivers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Driver %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

type ListImagesRes struct {
	All              []*model.ImageList // 本次同步的全部镜像
	Added            []*model.ImageList // 本次同步的新增镜像
	GetAuditLogError bool               // 拉取审计日志时是否出错
	HasErr           bool               // 同步数据时是否有错
}

type ListImagesRequest struct {
	NeedToReturnAll   bool
	NeedToReturnAdded bool
	GetAuditLogError  bool // 拉取审计日志时是否出错
}

type ListImagesAuditLog struct {
	StartAt int64 // 开始同步时间
	EndAt   int64 // 结束同步时间
}

type Extender struct {
	CreateImageExtender           ImageListExtender
	CreateOrAddRetryCountExtender CreateOrAddRetryCountExtender
	DeleteImageRetryExtender      DeleteImageRetryExtender
}

type ImageRetryRequest struct {
	RetryImages []model.SyncRetryImage
}

// Registry represents the required operations on a registry
type Registry interface {
	// // listRepos returns the entire list of repository.
	// listRepos() ([]string, error)
	//
	// // ListRepoTags returns the repo tags
	// ListRepoTags(string) ([]string, error)

	// GetRegistryConfig() config.RegisterConfig

	CheckProject(projectName string) error

	CreateProject(projectName string, public bool) error

	GetImage(projectName, fullRepoName, tag string) (*Image, error)

	Ping() error

	// DeleteImages delete special image
	DeleteImages(projectName, repoName, digest string) error
	// 是否支持增量同步
	SupportIncrementalSync(ctx context.Context) bool
	// ListImages return all images
	ListImages(ctx context.Context, extender Extender, req ListImagesRequest) (*ListImagesRes, error)
	ListImagesWithAuditLog(ctx context.Context, extender Extender, req ListImagesAuditLog) (*ListImagesRes, error)
	ImageRetry(ctx context.Context, extender Extender, req ImageRetryRequest) (*ListImagesRes, error)
}
