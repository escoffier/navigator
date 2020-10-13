package redclair

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
)

const (
	postLayerURI        = "http://%s:%d/v1/layers"
	getLayerFeaturesURI = "http://%s:%d/v1/layers/%s?vulnerabilities"
)

// VulnerabilityInfo ...
type VulnerabilityInfo struct {
	FeatureName    string `json:"featurename"`
	FeatureVersion string `json:"featureversion"`
	Vulnerability  string `json:"vulnerability"`
	Namespace      string `json:"namespace"`
	Description    string `json:"description"`
	Link           string `json:"link"`
	Severity       string `json:"severity"`
	FixedBy        string `json:"fixedby"`
}

// VulnerabilityInfoOfLayer ...
type VulnerabilityInfoOfLayer struct {
	Layer           string `json:"layer"`
	Vulnerabilities []VulnerabilityInfo
}

func (r *Redclair) analyzeLayers(ctx context.Context, pathToLayer string, imageName string, layerIDs []string) error {
	for _, layerID := range layerIDs {
		pathToLayer := fmt.Sprintf("http://%s:%d/%s/%s/layer.tar", r.externalAddr, r.externalPort, pathToLayer, layerID)
		log.Info().Str("image", imageName).Str("layerID", layerID).Str("pathToLayer", pathToLayer).Msg("Sending for analysis")

		// TODO: we need to know what is the parent layer here:
		// https://www.nearform.com/blog/static-analysis-of-docker-image-vulnerabilities-with-clair/
		// ParentName – this field is optional and has to be used if we want to analyze a docker image with more than one layer. In such case we need to push these layers in the right order by referencing its parent layer; otherwise, Clair will not be able to provide us with results of the entire docker image.

		err := r.analyzeLayer(ctx, pathToLayer, layerID, "")
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Redclair) analyzeLayer(ctx context.Context, path, layerName, parentLayerName string) error {
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

	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send request to Clair: %w", err))
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to read response from Clair: %w", err))
		}
		return NewClairError(http.StatusInternalServerError, fmt.Errorf("Expected Clair to return status 201, got: %v, body: %v", response.StatusCode, string(body)))
	}

	return nil
}

func (r Redclair) getVulnerabilities(ctx context.Context, imageName string, layerIDs []string) []VulnerabilityInfo {
	var vulnerabilities = make([]VulnerabilityInfo, 0)
	var vulnerabilitiesMap = make(map[VulnerabilityInfo]struct{})
	//Last layer gives you all the vulnerabilities of all layers <-- that is not right now, 2019-11-28
	//We scan all layer without parent, because schema 2 version 2 has no parent information
	//So we need to fetch all layers and distinguish them
	for _, layerID := range layerIDs {
		rawVulnerabilities, err := r.fetchLayerVulnerabilities(ctx, layerID)
		if err != nil {
			log.Warn().
				Msgf("Could not fetch vulnerabilities: %s of %s", layerID, imageName)
			continue
		}
		log.Info().Msgf("Fetched %s of %s", layerID, imageName)

		for _, feature := range rawVulnerabilities.Features {
			if len(feature.Vulnerabilities) > 0 {
				for _, vulnerability := range feature.Vulnerabilities {
					vulnerability := VulnerabilityInfo{
						feature.Name,
						feature.Version,
						vulnerability.Name,
						vulnerability.NamespaceName,
						vulnerability.Description,
						vulnerability.Link,
						vulnerability.Severity,
						vulnerability.FixedBy,
					}
					vulnerabilitiesMap[vulnerability] = struct{}{}
				}
			}
		}
	}
	for vulnerability := range vulnerabilitiesMap {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return vulnerabilities
}

func (r Redclair) fetchLayerVulnerabilities(ctx context.Context, layerID string) (NewerLayer, error) {

	reqPath := fmt.Sprintf(getLayerFeaturesURI, r.clairAddr, r.clairPort, layerID)
	request, err := http.NewRequest("GET", reqPath, nil)
	if err != nil {
		return NewerLayer{}, NewMalformedRequestError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare request to Clair: %w", err))
	}

	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return NewerLayer{}, NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send request to Clair: %w", err))
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return NewerLayer{}, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to read response from Clair: %w", err))
		}
		return NewerLayer{}, NewClairError(http.StatusInternalServerError, fmt.Errorf("Expected Clair to return status 201, got: %v, body: %v", response.StatusCode, string(body)))
	}

	var apiResponse NewerLayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return NewerLayer{}, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode reponse from Clair: %w", err))
	} else if apiResponse.Error != nil {
		return NewerLayer{}, NewClairError(http.StatusInternalServerError, fmt.Errorf("Clair responded with error: %v", apiResponse.Error.Message))

	}

	return apiResponse.Layer, nil
}
