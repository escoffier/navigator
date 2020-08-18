package redclair

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	postLayerURI        = "/v1/layers"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
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

// AnalyzeLayers tells Clair which layers to analyze
func AnalyzeLayers(
	imageName string,
	layerIDs []string,
	clairURL string,
	scannerIP string,
	scannerPort int,
) {
	tmpPath := fmt.Sprintf("http://%s:%d", scannerIP, scannerPort)

	for _, layerID := range layerIDs {
		log.Info().Msgf("[Scanner] Analyzing %s of %s", layerID, imageName)

		AnalyzeLayer(clairURL, tmpPath+"/"+layerID+"/layer.tar", layerID, "")
	}
}

// AnalyzeSingleLayer ...
func AnalyzeSingleLayer(layerID string, clairURL string, scannerIP string, scannerPort int) {
	tmpPath := fmt.Sprintf("http://%s:%d", scannerIP, scannerPort)

	AnalyzeLayer(clairURL, tmpPath+"/"+layerID+"/layer.tar", layerID, "")
}

// AnalyzeLayer pushes the required information to Clair to Scan the layer
func AnalyzeLayer(clairURL, path, layerName, parentLayerName string) {
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
			Msg("[Scanner] Could not analyze layer: payload is not JSON")
	}

	request, err := http.NewRequest("POST", clairURL+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Warn().
			Err(err).
			Msg("[Scanner] Could not analyze layer: could not prepare request for Clair")
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("[Scanner] Could not analyze layer: POST to Clair failed")
	} else {
		defer response.Body.Close()
		if response.StatusCode != 201 {
			body, _ := ioutil.ReadAll(response.Body)
			log.Warn().
				Msgf("[Scanner] Could not analyze layer: Clair responded with a failure: "+
					"Got response %d with message %s", response.StatusCode, string(body))
		}
	}
}

// GetVulnerabilities fetches vulnerabilities from Clair and extracts the required information
func GetVulnerabilities(imageName string, clairURL string, layerIDs []string) []VulnerabilityInfo {
	var vulnerabilities = make([]VulnerabilityInfo, 0)
	var vulnerabilitiesMap = make(map[VulnerabilityInfo]struct{})
	//Last layer gives you all the vulnerabilities of all layers <-- that is not right now, 2019-11-28
	//We scan all layer without parent, because schema 2 version 2 has no parent information
	//So we need to fetch all layers and distinguish them
	for _, layerID := range layerIDs {
		rawVulnerabilities, err := FetchLayerVulnerabilities(clairURL, layerID)
		if err != nil {
			log.Warn().
				Msgf("[Scanner] Could not fetch vulnerabilities: %s of %s", layerID, imageName)
			continue
		}
		log.Info().Msgf("[Scanner] Fetched %s of %s", layerID, imageName)

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

// GetAllLayerVulnerabilities ...
func GetAllLayerVulnerabilities(clairURL string, layerIDs []string) []VulnerabilityInfoOfLayer {
	var allLayerVulnerabilities []VulnerabilityInfoOfLayer
	for _, layerID := range layerIDs {
		var vulnerabilities = make([]VulnerabilityInfo, 0)
		rawVulnerabilities, err := FetchLayerVulnerabilities(clairURL, layerID)
		if err != nil {
			log.Warn().Msg("[Scanner] Could not fetch vulnerabilities. " +
				"No features have been detected in the image. " +
				"This usually means that the image isn't supported by Clair")
		}

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
					vulnerabilities = append(vulnerabilities, vulnerability)
				}
			}
		}

		allLayerVulnerabilities = append(
			allLayerVulnerabilities, VulnerabilityInfoOfLayer{layerID, vulnerabilities})
	}
	return allLayerVulnerabilities
}

// GetVulnerabilitiesOfSingleLayer ...
func GetVulnerabilitiesOfSingleLayer(clairURL string, layerID string) []VulnerabilityInfo {
	var vulnerabilities = make([]VulnerabilityInfo, 0)
	//Fetch only one layer
	rawVulnerabilities, err := FetchLayerVulnerabilities(clairURL, layerID)
	if err != nil {
		log.Warn().Msg("[Scanner] Could not fetch vulnerabilities. " +
			"No features have been detected in the image. " +
			"This usually means that the image isn't supported by Clair")
	}

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
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}
	return vulnerabilities
}

// FetchLayerVulnerabilities fetches vulnerabilities from Clair
func FetchLayerVulnerabilities(clairURL string, layerID string) (NewerLayer, error) {
	url := clairURL + fmt.Sprintf(getLayerFeaturesURI, layerID)
	response, err := http.Get(url)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("[Scanner] Fetch vulnerabilities, Clair responded with a failure")
		return NewerLayer{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		log.Warn().
			Msgf("[Scanner] Fetch vulnerabilities, Clair responded with a failure: "+
				"Got response %d with message %s", response.StatusCode, string(body))
		return NewerLayer{}, err
	}

	var apiResponse NewerLayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		log.Warn().
			Err(err).
			Msg("[Scanner] Fetch vulnerabilities, Could not decode response")
		return NewerLayer{}, err
	} else if apiResponse.Error != nil {
		log.Warn().
			Msgf("[Scanner] Fetch vulnerabilities, Response contains errors %s",
				apiResponse.Error.Message)
		return NewerLayer{}, err
	}

	return apiResponse.Layer, nil
}
