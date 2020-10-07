package redclair

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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

func (r *Redclair) analyzeLayers(
	pathToLayer string,
	imageName string,
	layerIDs []string,
) {

	for _, layerID := range layerIDs {
		pathToLayer := fmt.Sprintf("http://%s:%d/%s/%s/layer.tar", r.externalAddr, r.externalPort, pathToLayer, layerID)
		log.Info().Str("image", imageName).Str("layerID", layerID).Str("pathToLayer", pathToLayer).Msg("Sending for analysis")

		// TODO: we need to know what is the parent layer here:
		// https://www.nearform.com/blog/static-analysis-of-docker-image-vulnerabilities-with-clair/
		// ParentName – this field is optional and has to be used if we want to analyze a docker image with more than one layer. In such case we need to push these layers in the right order by referencing its parent layer; otherwise, Clair will not be able to provide us with results of the entire docker image.

		r.analyzeLayer(pathToLayer, layerID, "")
	}
}

func (r *Redclair) analyzeLayer(path, layerName, parentLayerName string) {
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
		log.Warn().
			Err(err).
			Msg("Could not analyze layer: payload is not JSON")
	}

	reqPath := fmt.Sprintf(postLayerURI, r.clairAddr, r.clairPort)
	request, err := http.NewRequest("POST", reqPath, bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Could not analyze layer: could not prepare request for Clair")
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Could not analyze layer: POST to Clair failed")
	} else {
		defer response.Body.Close()
		if response.StatusCode != 201 {
			body, _ := ioutil.ReadAll(response.Body)
			log.Warn().
				Msgf("Could not analyze layer: Clair responded with a failure: "+
					"Got response %d with message %s", response.StatusCode, string(body))
		}
	}
}

// GetVulnerabilities fetches vulnerabilities from Clair and extracts the required information
func (r Redclair) GetVulnerabilities(imageName string, layerIDs []string) []VulnerabilityInfo {
	var vulnerabilities = make([]VulnerabilityInfo, 0)
	var vulnerabilitiesMap = make(map[VulnerabilityInfo]struct{})
	//Last layer gives you all the vulnerabilities of all layers <-- that is not right now, 2019-11-28
	//We scan all layer without parent, because schema 2 version 2 has no parent information
	//So we need to fetch all layers and distinguish them
	for _, layerID := range layerIDs {
		rawVulnerabilities, err := r.FetchLayerVulnerabilities(layerID)
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

// FetchLayerVulnerabilities fetches vulnerabilities from Clair
func (r Redclair) FetchLayerVulnerabilities(layerID string) (NewerLayer, error) {

	url := fmt.Sprintf(getLayerFeaturesURI, r.clairAddr, r.clairPort, layerID)
	response, err := http.Get(url)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Fetch vulnerabilities, Clair responded with a failure")
		return NewerLayer{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		log.Warn().
			Msgf("Fetch vulnerabilities, Clair responded with a failure: "+
				"Got response %d with message %s", response.StatusCode, string(body))
		return NewerLayer{}, err
	}

	var apiResponse NewerLayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		log.Warn().
			Err(err).
			Msg("Fetch vulnerabilities, Could not decode response")
		return NewerLayer{}, err
	} else if apiResponse.Error != nil {
		log.Warn().
			Msgf("Fetch vulnerabilities, Response contains errors %s",
				apiResponse.Error.Message)
		return NewerLayer{}, err
	}

	return apiResponse.Layer, nil
}
