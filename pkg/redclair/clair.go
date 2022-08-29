package redclair

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/httputil"
)

const (
	postLayerURI        = "http://%s:%d/v1/layers"
	getLayerFeaturesURI = "http://%s:%d/v1/layers/%s?vulnerabilities"
)

func (r *Redclair) scheduleLayerScanInClair(ctx context.Context, path, layerName, parentLayerName string) error {
	payload := NewerLayerEnvelope{
		Layer: NewerLayer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "Docker",
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return NewMalformedRequestError(http.StatusInternalServerError, fmt.Errorf("Failed to marshal request to Clair: %w", err))
	}

	reqPath := fmt.Sprintf(postLayerURI, r.clairAddr, r.clairPort)
	request, err := http.NewRequest("POST", reqPath, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return NewMalformedRequestError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare request to Clair: %w", err))
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := httputil.DefaultClient.Do(request.WithContext(ctx))
	if err != nil {
		return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send request to Clair: %w", err))
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to read response from Clair: %w", err))
		}

		if response.StatusCode >= 300 {
			clairResponseError := &NewerLayerEnvelope{}
			err := json.Unmarshal(body, clairResponseError)
			if err != nil {
				return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to parse response body from Clair: %w", err))
			}

			if response.StatusCode == http.StatusBadRequest {
				if strings.Contains(clairResponseError.Error.Message, "parent layer is unknown") {
					return NewClairMissingParentLayerError(http.StatusBadRequest, fmt.Errorf("Provided parent layer name %s does not exist in Clair", parentLayerName))
				}
			}

			if response.StatusCode == http.StatusUnprocessableEntity {
				// Possible cause: "worker: OS and/or package manager are not supported"
				return NewClairUnprocessableLayerError(http.StatusBadRequest, fmt.Errorf("Clair reports that layer is unprocessable: %s", clairResponseError.Error.Message))
			}
		}

		return NewClairError(http.StatusInternalServerError, fmt.Errorf("Expected Clair to return status 201, got: %v, body: %v", response.StatusCode, string(body)))
	}

	return nil
}

func (r *Redclair) getTransformedLayerScanResultFromClair(ctx context.Context, digest string) (string, []model.VulnerabilityInfo, error) {
	var vulnerabilities = make([]model.VulnerabilityInfo, 0)
	var vulnerabilitiesMap = make(map[string]model.VulnerabilityInfo)
	rawVulnerabilities, err := r.fetchLayerVulnerabilitiesFromClair(ctx, digest)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, fmt.Errorf("Could not fetch vulnerabilities of %s: %w", digest, err)
	}
	zerolog.Ctx(ctx).Info().Msgf("Fetched vulnerabilities of %s", digest)

	for _, feature := range rawVulnerabilities.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {

				var meta metadataT
				json.Unmarshal([]byte(vulnerability.Metadata), &meta)
				if err != nil {
					zerolog.Ctx(ctx).Warn().Err(err).
						Str("raw", fmt.Sprintf("%+v", vulnerability.Metadata)).
						Msgf("Failed to unmarshal metadata of %s", digest)
					return "", []model.VulnerabilityInfo{}, fmt.Errorf("Failed to unmarshal metadata of %s: %w", digest, err)
				}

				newVuln := model.VulnerabilityInfo{
					FeatureName:    feature.Name,
					FeatureVersion: feature.Version,
					ID:             vulnerability.Name,
					Namespace:      vulnerability.NamespaceName,
					Description:    vulnerability.Description,
					Links:          []string{vulnerability.Link},
					Severity:       vulnerability.Severity,
					FixedBy:        vulnerability.FixedBy,

					CVSS: model.CVSSVulnerabilityInfo{
						CVSSv2Vector:              meta.NVD.CVSSv2.Vectors,
						CVSSv2Score:               meta.NVD.CVSSv2.Score.String(),
						CVSSv3Vector:              meta.NVD.CVSSv3.Vectors,
						CVSSv3Score:               meta.NVD.CVSSv3.Score.String(),
						CVSSv3ImpactScore:         meta.NVD.CVSSv3.ImpactScore.String(),
						CVSSv3ExploitabilityScore: meta.NVD.CVSSv3.ExploitabilityScore.String(),
					},
				}

				for _, cnvd := range meta.CNVD {
					newVuln.CNVDs = append(newVuln.CNVDs, model.CNVDVulnerabilityInfo{
						Number:      cnvd.Number,
						Title:       cnvd.Title,
						Severity:    cnvd.Severity,
						RefLink:     cnvd.RefLink,
						Description: cnvd.Description,
					})
				}

				vulnerabilitiesMap[newVuln.ID] = newVuln
			}
		}
	}
	for _, vulnerability := range vulnerabilitiesMap {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return rawVulnerabilities.NamespaceName, vulnerabilities, nil
}

func (r *Redclair) fetchLayerVulnerabilitiesFromClair(ctx context.Context, layerID string) (NewerLayer, error) {

	reqPath := fmt.Sprintf(getLayerFeaturesURI, r.clairAddr, r.clairPort, layerID)
	request, err := http.NewRequest("GET", reqPath, nil)
	if err != nil {
		return NewerLayer{}, NewMalformedRequestError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare request to Clair: %w", err))
	}

	response, err := httputil.DefaultClient.Do(request.WithContext(ctx))
	if err != nil {
		return NewerLayer{}, NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send request to Clair: %w", err))
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return NewerLayer{}, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to read response from Clair: %w", err))
		}
		return NewerLayer{}, NewClairError(http.StatusInternalServerError, fmt.Errorf("Expected Clair to return status 200, got: %v, body: %v", response.StatusCode, string(body)))
	}

	var apiResponse NewerLayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return NewerLayer{}, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode reponse from Clair: %w", err))
	}
	if apiResponse.Error != nil {
		return NewerLayer{}, NewClairError(http.StatusInternalServerError, fmt.Errorf("Clair responded with error: %v", apiResponse.Error.Message))
	}

	return apiResponse.Layer, nil
}
