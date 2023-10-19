package util

import "github.com/google/go-containerregistry/pkg/name"

func ParseImage(image string) (string, string, string) {
	var repo, imageName, tag string
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(image, nameOpts...)
	if err != nil {
		return "", "", ""
	}
	repo = ref.Context().RegistryStr()
	imageName = ref.Context().RepositoryStr()
	tag = ref.Identifier()
	return repo, imageName, tag
}
