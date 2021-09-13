// Package registry defines the  models and a common interface for
// registry implementations.
package registry

type RegisterConfig struct {
	RegistryId    int64
	URL           string
	Username      string
	Password      string
	SkipTLSVerify bool
	Region        string
	AccessKey     string
	SecretKey     string
	Insecure      bool
}

// ImageListExtender is a function that can do some stuff when sync one image
type ImageListExtender func(conf RegisterConfig, image Image) error

// Registry represents the required operations on a registry
type Registry interface {
	// // ListRepos returns the entire list of repository.
	// ListRepos() ([]string, error)
	//
	// // ListRepoTags returns the repo tags
	// ListRepoTags(string) ([]string, error)

	GetRegistryConfig() RegisterConfig

	CheckProject(projectName string) error

	CreateProject(projectName string, public bool) error

	GetImage(projectName, fullRepoName, tag string) (*Image, error)

	// DeleteImages delete special image
	DeleteImages(projectName, repoName, digest string) error

	// ListImages return all images
	ListImages(extender ImageListExtender) ([]Image, error)
}
