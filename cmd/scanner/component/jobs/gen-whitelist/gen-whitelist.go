package genwhitelist

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	dockerarchive "github.com/docker/docker/pkg/archive"
	filecheck "gitlab.com/piccolo_su/vegeta/cmd/file-checker"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	JobName = "gen-whitelist"
)

type GenWhitelist struct {
}

func (s *GenWhitelist) addFileToList(header *tar.Header, path string, whitelist *[]filecheck.WhitelistFile, tarReader *tar.Reader, mp map[string]string) {
	// resolvedSymlink, err := filepath.EvalSymlinks(header.Name)
	// if err != nil {
	// 	logging.GetLogger().Warn().Err(err).Msgf("Failed to resolve symlink: path %s resolvedPath %s", header.Name, resolvedSymlink)
	// 	return
	// }
	file, err := ioutil.TempFile("/tmp", "check")
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msgf("Failed to create tmp file path %s resolvedPath %s", header.Name, header.Linkname)
		return
	}
	defer func() {
		err := os.Remove(file.Name())
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("remove file error %v", file.Name())
		}
	}()
	_, err = io.Copy(file, tarReader)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msgf("Failed copy file path %s resolvedPath %s", header.Name, header.Linkname)
		return
	}
	file, err = os.Open(file.Name())
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msgf("Failed to open file: path %s resolvedPath %s", header.Name, header.Linkname)
		return
	}
	defer func() {
		if err = file.Close(); err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("Failed to close file: path %s resolvedPath %s", header.Name, header.Linkname)
		}
	}()
	checksum, err := filecheck.CalculateChecksum(file)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msgf("Failed to calculate checksum: path %s resolvedPath %s", header.Name, header.Linkname)
		return
	}
	*whitelist = append(*whitelist, filecheck.WhitelistFile{
		Name:     "/" + header.Name,
		Checksum: fmt.Sprintf("%X", checksum),
	})
	mp[header.Name] = fmt.Sprintf("%X", checksum)
}

func (s *GenWhitelist) GenWhitelistFromLayer(path string, whitelist *[]filecheck.WhitelistFile) error {
	tarFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Failed to advance tarReader: %w", err)
	}
	defer func() { _ = tarFile.Close() }() // close the file

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return fmt.Errorf("Failed to DecompressStream: %w", err)
	}

	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader
	mpLink := make(map[string]string)
	mpSum := make(map[string]string)
	tarReader := tar.NewReader(decompressStreamReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("Failed to advance tarReader: %w", err)
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}
		perm := header.FileInfo().Mode().Perm()
		f := perm & os.FileMode(73)
		if uint32(f) == uint32(73) && header.FileInfo().Mode().IsRegular() {
			if header.Typeflag == tar.TypeLink || header.Typeflag == tar.TypeSymlink {
				mpLink[header.Name] = header.Linkname
				continue
			}
			s.addFileToList(header, path, whitelist, tarReader, mpSum)
		}
	}
	for k := range mpLink {
		*whitelist = append(*whitelist, filecheck.WhitelistFile{
			Name:     k,
			Checksum: mpSum[mpLink[k]],
		})
	}
	return nil
}

func (s *GenWhitelist) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	layers, ok := param["layers"].([]string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'layers' in parameter")
		return nil, errors.New("miss 'layers' in parameter")
	}
	digest, ok := param["digest"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'digest' in parameter")
		return nil, errors.New("miss 'digest' in parameter")
	}

	layersFilePath, ok := param["layersFilePath"].([]string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'layersFilePath' in parameter")
		return nil, errors.New("miss 'layersFilePath' in parameter")
	}
	whitelist := make([]filecheck.WhitelistFile, 0)

	for i := 1; i < len(layers); i++ {
		err := s.GenWhitelistFromLayer(filepath.Join(layersFilePath[i], "layer.tar"), &whitelist)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("GenWhitelistFromLayer error path:%s", filepath.Join(layersFilePath[i], "layer.tar"))
		}
	}
	whitelist = filecheck.Unique(whitelist)
	sort.Slice(whitelist, func(i, j int) bool {
		return whitelist[i].Name < whitelist[j].Name
	})
	whitelistByte, err := json.Marshal(whitelist)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Gen-WhiteList marshal json error:")
		return nil, err
	}
	whitelists := model.ScanWhitelist{}
	whitelists.Digest = digest
	whitelists.WhitelistJSON = whitelistByte
	scannerOrm := store.GetScannerDb()
	err = scannerOrm.InsertToScanWhitelist(context.Background(), &whitelists)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func init() {
	err := jobs.Register(JobName, newJob)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("jobName", JobName).Msg("init job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	i := &GenWhitelist{}
	return i, nil
}
