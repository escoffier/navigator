package redclair

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/heroku/docker-registry-client/registry"
	"github.com/rs/zerolog"
	layerManage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/layer_manage"
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

func (r *Redclair) ScanLayer(ctx context.Context, hub *registry.Registry, digest, parentDigest, repository string, client *layerManage.LocalLayerManageClient, scanTask model.ScanTask) (string, []model.VulnerabilityInfo, []model.Sensitive, error) {
	/*pathToLayersInFS, err := r.CreateTempLayerDigestDir(digest)
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
	}*/
	layerPath, httpLayer, err := r.GetLayerPath(ctx, client, scanTask, digest)
	defer r.DeleteLayerPath(ctx, client, digest)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Get local layer manage client err %v", err)
	}
	info, err := os.Stat(layerPath)
	if err != nil {
		//client.DeleteLayer(digest)
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("os.Stat failed: %w", err)
	}
	pathToLayersInFS := layerPath[0 : len(layerPath)-10]
	zerolog.Ctx(ctx).Info().
		Str("repository", repository).
		Str("layerDigest", digest).
		Int64("size", info.Size()).
		Str("path", layerPath).
		Msg("Layer saved locally")

	//Analyze the layers
	//pathToLayerInHTTP, err := filepath.Rel(r.httpRootDir, pathToLayersInFS)
	//zerolog.Ctx(ctx).Info().Str("pathToLayerInHTTP:", pathToLayerInHTTP).Msg("LayerHTTP")
	//if err != nil {
	//client.DeleteLayer(digest)
	//	return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to get relative path between %s and %s: %w", httpServerRootDir, pathToLayerInHTTP, err)
	//}
	//pathToLayerInHTTP = pathToLayerInHTTP[15:]
	//pathToLayer := fmt.Sprintf("http://%s:6677/%s", r.externalAddr, pathToLayerInHTTP)
	zerolog.Ctx(ctx).Info().Str("httpLayer:", httpLayer).Str("httpRootDir", r.httpRootDir).Msg("PathToLayer")
	err = r.scheduleLayerScanInClair(ctx, httpLayer, digest, parentDigest)
	if err != nil {
		//client.DeleteLayer(digest)
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to schedule layer scan in Clair: %w", err)
	}

	namespaceName, vulnerabilities, err := r.getTransformedLayerScanResultFromClair(ctx, digest)
	if err != nil {
		//client.DeleteLayer(digest)
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to get vulnerabilities: %w", err)
	}

	if !r.offlineMode {
		err = r.enrichWithCNNVD(ctx, vulnerabilities)
		if err != nil {
			//client.DeleteLayer(digest)
			//return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to enrich vuln info with CNNVD: %w", err)
		}
	}

	err = r.recalculateSeverity(ctx, vulnerabilities)
	if err != nil {
		//client.DeleteLayer(digest)
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to recalculate severity: %w", err)
	}

	sensitiveFiles, err := r.findSensitiveFileNamesInImage(filepath.Join(pathToLayersInFS, "layer.tar"), r.sensitiveFilenameRegExp)
	if err != nil {
		//client.DeleteLayer(digest)
		return "", []model.VulnerabilityInfo{}, []model.Sensitive{}, fmt.Errorf("Failed to run search for sensitive filenames: %w", err)
	}
	//client.DeleteLayer(digest)
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
func (r *Redclair) GetLayerPath(ctx context.Context, client *layerManage.LocalLayerManageClient, scanTask model.ScanTask, digest string) (string, string, error) {
	/*client, err := layerManage.NewLocalLayerManageClient(llms)
	if err != nil {
		return "", fmt.Errorf("new local layer manage client err %v", err)
	}*/
	zerolog.Ctx(ctx).Info().Str("Digest:", digest).Msg("Clair Get Layer")
	username, password, err := r.decodeUsernamePassword(scanTask)
	if err != nil {
		return "", "", fmt.Errorf("decodeUsernamePassword err %v", err)
	}
	layerUrl, httpLayer, err := client.GetLayer(username, password, scanTask.URL, scanTask.Repository, digest, true)
	if err != nil {
		return "", "", fmt.Errorf("get layer err %v", err)
	}
	return layerUrl, httpLayer, nil
}

func (r *Redclair) DeleteLayerPath(ctx context.Context, client *layerManage.LocalLayerManageClient, digest string) {
	zerolog.Ctx(ctx).Info().Str("Digest:", digest).Msg("Clair Delete Layer")
	client.DeleteLayer(digest)
}

func (r *Redclair) decodeUsernamePassword(scanTask model.ScanTask) (string, string, error) {
	// scanTask.Authorization == Basic cm9ib3QkdHMt...

	headerSplit := strings.Split(scanTask.Authorization, " ")
	if len(headerSplit) != 2 {
		return "", "", fmt.Errorf("Expected 'Basic ASDF' format, but got different")
	}
	b64Encoded := headerSplit[1]

	decodedHeader, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		return "", "", fmt.Errorf("Couldn't decode auth string: %w", err)
	}

	// decodedHeader == robot$ts-cdffae66-0edd-11eb-91a9-4e1d0aed31d4:eyJhbGciOiJSUzI1...

	usernamePasswordArr := strings.Split(string(decodedHeader), ":")
	if len(usernamePasswordArr) != 2 {
		return "", "", fmt.Errorf("Expected 'username:password' format, but got different")
	}

	username := usernamePasswordArr[0]
	password := usernamePasswordArr[1]

	return username, password, nil
}
