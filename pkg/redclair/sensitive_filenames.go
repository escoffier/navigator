package redclair

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"regexp"

	dockerarchive "github.com/docker/docker/pkg/archive"
)

type SecretPattern struct {
	DescriptionEn string `json:"descriptionEn"`
	DescriptionZh string `json:"descriptionZh"`
	Type          string `json:"secret_type"`
	Value         string `json:"value"`
}

type SensitiveDescription struct {
	En string `json:"en"`
	Zh string `json:"zh"`
}

type Sensitive struct {
	Name          string `json:"name" bson:"name"`
	Description   string `json:"description" bson:"description"`
	DescriptionEn string `json:"description_en" bson:"description_en"`
	DescriptionZh string `json:"description_zh" bson:"description_zh"`
}

func (r *Redclair) findSensitiveFileNamesInImage(tarFileName string, sensitiveRegExp *regexp.Regexp) ([]Sensitive, error) {
	sensitiveFiles := []Sensitive{}

	tarFile, err := os.Open(tarFileName)
	if err != nil {
		return sensitiveFiles, fmt.Errorf("Failed to open %s: %w", tarFileName, err)
	}
	defer tarFile.Close()

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return sensitiveFiles, fmt.Errorf("Failed to create dockerarchive decompressed stream: %w", err)
	}
	defer decompressStreamReader.Close()

	tarReader := tar.NewReader(decompressStreamReader)
	sensitiveFilenames := []string{}
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return sensitiveFiles, fmt.Errorf("Failed to advance tarReader: %w", err)
		}
		if r.sensitiveFilenameRegExp.FindString(header.Name) != "" {
			if err == nil {
				sensitiveFilenames = append(sensitiveFilenames, header.Name)
			}
		}
	}

	enrichedSensitiveFiles := r.enrichSensitiveFilesWithDescriptions(sensitiveFilenames)
	return enrichedSensitiveFiles, nil
}

func (r *Redclair) enrichSensitiveFilesWithDescriptions(sensitiveFiles []string) []Sensitive {
	imageSensitiveFiles := make([]Sensitive, 0)
	for _, f := range sensitiveFiles {
		for re, description := range r.sensitiveFilenameRegExpMap {
			//
			// You may ask - why are we applying regex twice?
			// 1. here: r.sensitiveFilenameRegExp.FindString(header.Name)
			// 2. and here, r.sensitiveFilenameRegExpMap, below this comment?
			//
			// I'm glad you ask.
			//
			// sensitiveFilenameRegExp is a single regex state machine that checks
			// for all possible sensitive filenames. In principle, it should be faster
			// than iterating over single-filename regexes.
			// So we use it to find sensitive filenames in the first place.
			//
			// Then we use sensitiveFilenameRegExpMap here, to add descriptions.
			//
			// Is it faster? Is it less memory intensive?
			// I don't know. We may want to check whether we actually need two
			// regex passes like this.
			// My suspicion is that we don't need two passes.
			// But I'm going to leave it as it is right now, as I don't think
			// it's very important.
			//
			if re.MatchString(f) {
				imageSensitiveFiles = append(imageSensitiveFiles, Sensitive{
					Name:          f,
					DescriptionEn: description.En,
					DescriptionZh: description.Zh,
				})
			}
		}
	}
	return imageSensitiveFiles
}
