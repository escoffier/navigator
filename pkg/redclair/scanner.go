package redclair

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/heroku/docker-registry-client/registry"
	dig "github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// VulnerabilitiesWhitelist ...
type VulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            // [key: CVE and value: CVE description]
	Images           map[string]map[string]string // image name with [key: CVE and value: CVE desc]
}

const (
	httpServerRootDir        = "redclair-images"
	httpServerImageDirPrefix = "image-"
)

var nvmRegExp = regexp.MustCompile(`nvm\suse\sv[0-9\.]+`)
var nvmVersionRegExp = regexp.MustCompile(`[0-9\.]+`)

// var mapLock sync.Mutex

// Pattern ...
type Pattern struct {
	Description string `json:"description"`
	SecretType  string `json:"secret_type"`
	Value       string `json:"value"`
	Regex       *regexp.Regexp
}

func (r *Redclair) ScanLayer(ctx context.Context, hub *registry.Registry, digest, parentDigest, repository string) (string, []model.VulnerabilityInfo, []model.Sensitive, error) {
	pathToLayersInFS, err := r.CreateTempLayerDigestDir(digest)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Couldn't make image temp dir in %s: %w", pathToLayersInFS, err)
	}
	defer func() {
		err := os.RemoveAll(pathToLayersInFS)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Str("path", pathToLayersInFS).Msg("Couldn't remove image temp dir, ignoring")
		}
	}()
	d := dig.NewDigestFromHex(strings.Split(digest, ":")[0], strings.Split(digest, ":")[1])

	reader, err := hub.DownloadBlob(repository, d)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to download blob %s: %w", repository, err)
	}
	defer reader.Close()

	outFile, err := os.Create(pathToLayersInFS + "/layer.tar")
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to create layer.tar file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, reader)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to copy file contents: %w", err)
	}

	info, err := os.Stat(pathToLayersInFS + "/layer.tar")
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("os.Stat failed: %w", err)
	}

	zerolog.Ctx(ctx).Info().
		Str("repository", repository).
		Str("layerDigest", digest).
		Int64("size", info.Size()).
		Str("path", pathToLayersInFS+"/layer.tar").
		Msg("Layer saved locally")

	//Analyze the layers
	pathToLayerInHTTP, err := filepath.Rel(r.httpRootDir, pathToLayersInFS)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to get relative path between %s and %s: %w", httpServerRootDir, pathToLayerInHTTP, err)
	}

	pathToLayer := fmt.Sprintf("http://%s:%d/%s/layer.tar", r.externalAddr, r.externalPort, pathToLayerInHTTP)
	err = r.scheduleLayerScanInClair(ctx, pathToLayer, digest, parentDigest)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to schedule layer scan in Clair: %w", err)
	}

	namespaceName, vulnerabilities, err := r.getTransformedLayerScanResultFromClair(ctx, digest)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to get vulnerabilities: %w", err)
	}

	if !r.offlineMode {
		err = r.enrichWithCNNVD(ctx, vulnerabilities)
		if err != nil {
			return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to enrich vuln info with CNNVD: %w", err)
		}
	}

	err = r.recalculateSeverity(ctx, vulnerabilities)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to recalculate severity: %w", err)
	}

	sensitiveFiles, err := r.findSensitiveFileNamesInImage(filepath.Join(pathToLayersInFS, "layer.tar"), r.sensitiveFilenameRegExp)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to run search for sensitive filenames: %w", err)
	}

	return namespaceName, vulnerabilities, sensitiveFiles, nil
}

func (r *Redclair) recalculateSeverity(ctx context.Context, vulns []model.VulnerabilityInfo) error {
	for i, vuln := range vulns {

		if vuln.CVSS.CVSSv2Score == "" {
			continue
		}

		// It's a string that contains one decimal place.
		// Convert to an int without decimals by removing the "."
		// (effectively multiplies by 10)

		score, err := strconv.ParseFloat(vuln.CVSS.CVSSv2Score, 64)
		if err != nil {
			return fmt.Errorf("Failed to parse CVSSv2 score: %w", err)
		}
		severity := GetSeverityFromScore(int64(score * 10))
		vulns[i].Severity = severity
	}
	return nil
}
