package component

import (
	"errors"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	// ErrReportNotFound ...
	ErrReportNotFound = errors.New("no report found")
)

// NewTaskByNameTag ...
func NewTaskByNameTag(nameTag string, forceRescan bool, digest ...string) (model.ScanTask, error) {
	var index = strings.LastIndex(nameTag, ":")
	var digestImage string
	var err error

	if len(digest) > 0 {
		digestImage = digest[0]
	} else {
		digestImage, _ = getImageDigest(nameTag)
	}

	if index == -1 {
		return model.ScanTask{
			Image:       nameTag,
			Tag:         "latest",
			ImageDigest: digestImage,
			ForceRescan: forceRescan,
		}, err
	}

	var image = nameTag[0:index]
	var tag = nameTag[index+1:]
	if strings.Contains(image, ":") {
		return model.ScanTask{}, errors.New("name-tag string format illegal")
	}
	return model.ScanTask{
		Image:       nameTag,
		Tag:         tag,
		ImageDigest: digestImage,
		ForceRescan: forceRescan,
	}, err
}

func getImageDigest(imageName string) (string, error) {
	// TODO get image digest from image registry
	return "", nil
}
