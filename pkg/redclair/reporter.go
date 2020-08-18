package redclair

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"unsafe"

	"github.com/olekukonko/tablewriter"
)

// VulnerabilityReport ...
type VulnerabilityReport struct {
	Image           string              `json:"image"`
	Hash            string              `json:"hash"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

// LayerCommand ...
type LayerCommand struct {
	Layer   string `json:"layer"`
	Command string `json:"command"`
}

// VulnerabilityLayerReport ...
type VulnerabilityLayerReport struct {
	Layer           string              `json:"layer"`
	Command         string              `json:"command"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

// VulnerabilityLayerGroupReport ...
type VulnerabilityLayerGroupReport []VulnerabilityLayerReport

// VulnerabilityReportOfSingleLayer ...
type VulnerabilityReportOfSingleLayer struct {
	Layer           string              `json:"layer"`
	Image           string              `json:"image"`
	Hash            string              `json:"hash"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

// InSlice ...
func InSlice(val VulnerabilityInfo, slice []VulnerabilityInfo) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// SliceSubtract ...
func SliceSubtract(slice1, slice2 []VulnerabilityInfo) (diffslice []VulnerabilityInfo) {
	if len(slice1) < len(slice2) {
		t := slice1
		slice1 = slice2
		slice2 = t
	}
	for _, v := range slice1 {
		if !InSlice(v, slice2) {
			diffslice = append(diffslice, v)
		}
	}
	return
}

// SortBySeverity ...
func SortBySeverity(vulnerabilities []VulnerabilityInfo) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return SeverityMap[vulnerabilities[i].Severity] < SeverityMap[vulnerabilities[j].Severity]
	})
}

// FormatStatus ...
func FormatStatus(status string) string {
	if status == "Approved" {
		return fmt.Sprintf(NoticeColor, status)
	}
	return fmt.Sprintf(ErrorColor, status)
}

// FormatTableData ...
func FormatTableData(vulnerabilities []VulnerabilityInfo, unapproved []string) [][]string {
	formatted := make([][]string, len(vulnerabilities))
	for i, vulnerability := range vulnerabilities {
		status := "Approved"
		for _, u := range unapproved {
			if vulnerability.Vulnerability == u {
				status = "Unapproved"
			}
		}
		formatted[i] = []string{
			FormatStatus(status),
			vulnerability.Severity + " " + vulnerability.Vulnerability,
			vulnerability.FeatureName,
			vulnerability.FeatureVersion,
			vulnerability.Description + "\n\n" + vulnerability.Link,
		}
	}
	return formatted
}

// PrintTable ...
func PrintTable(vulnerabilities []VulnerabilityInfo, unapproved []string) {
	header := []string{"Status", "CVE Severity", "Package Name", "Package Version", "CVE Description"}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowSeparator("-")
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.AppendBulk(FormatTableData(vulnerabilities, unapproved))
	table.Render()
}

// FilterApproved ...
func FilterApproved(
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	reportAll bool,
) []VulnerabilityInfo {
	if reportAll {
		return vulnerabilities
	}

	vulns := make([]VulnerabilityInfo, 0)
	for _, vuln := range vulnerabilities {
		for _, u := range unapproved {
			if vuln.Vulnerability == u {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns
}

// reportJSON ...
func reportJSON(
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	hash string,
) []byte {
	report := &VulnerabilityReport{
		Image:           imageName,
		Hash:            hash,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	j, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: report is not proper JSON %v", err)
		return nil
	}
	return j
}

// ReportToConsole ...
func ReportToConsole(
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	reportAll bool,
	jsonFormat bool,
	hash string,
) {
	if jsonFormat {
		rj := reportJSON(imageName, vulnerabilities, unapproved, hash)
		fmt.Print(*(*string)(unsafe.Pointer(&rj)))
	} else {
		if len(vulnerabilities) > 0 {
			log.Warn().Msgf("[Scanner] Image [%s] contains %d total vulnerabilities",
				imageName, len(vulnerabilities))

			vulnerabilities = FilterApproved(vulnerabilities, unapproved, reportAll)
			SortBySeverity(vulnerabilities)

			if len(unapproved) > 0 {
				log.Error().Msgf("[Scanner] Image [%s] contains %d unapproved vulnerabilities",
					imageName, len(unapproved))
				PrintTable(vulnerabilities, unapproved)
			} else {
				log.Info().Msgf("[Scanner] Image [%s] contains NO unapproved vulnerabilities",
					imageName)
				if reportAll {
					PrintTable(vulnerabilities, unapproved)
				}
			}
		} else {
			log.Info().Msgf("[Scanner] Image [%s] contains NO unapproved vulnerabilities",
				imageName)
		}
	}
}

// ReportToConsoleOfDividedLayer ...
func ReportToConsoleOfDividedLayer(
	imageName string,
	vulnerabilitiesGroup []VulnerabilityInfoOfLayer,
	jsonFormat bool,
) {
	if jsonFormat {
		log.Warn().Msg("[Scanner] Print JSON format report of divided layers " +
			"to console is not supported yet.")
	} else {
		if len(vulnerabilitiesGroup) > 0 {
			log.Warn().Msgf("[Scanner] Image [%s] contains %d layers",
				imageName, len(vulnerabilitiesGroup))
			for i, vulnerabilityInfo := range vulnerabilitiesGroup {
				if i == 0 {
					log.Error().Msgf("[Scanner] Layer [%s] has %d vulnerabilities",
						vulnerabilityInfo.Layer, len(vulnerabilityInfo.Vulnerabilities))
					continue
				}
				newVulnerabilities := SliceSubtract(vulnerabilityInfo.Vulnerabilities,
					vulnerabilitiesGroup[i-1].Vulnerabilities)
				if len(newVulnerabilities) > 0 {
					log.Error().Msgf("[Scanner] Layer [%s] has %d vulnerabilities",
						vulnerabilityInfo.Layer, len(newVulnerabilities))
				}
			}
		} else {
			log.Info().Msgf("[Scanner] Image [%s] contains NO layers", vulnerabilitiesGroup)
		}
	}
}

// ReportJSONOfSingleLAyer ...
func ReportJSONOfSingleLAyer(
	layerID string,
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	hash string,
) []byte {
	report := &VulnerabilityReportOfSingleLayer{
		Layer:           layerID,
		Image:           imageName,
		Hash:            hash,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: report is not proper JSON %v", err)
		return nil
	}
	return reportJSON
}

// ReportToConsoleOfSingleLayer ...
func ReportToConsoleOfSingleLayer(
	layerID string,
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	reportAll bool,
	jsonFormat bool,
	hash string,
) {
	if jsonFormat {
		reportJSON := ReportJSONOfSingleLAyer(layerID, imageName, vulnerabilities, unapproved, hash)
		fmt.Print(*(*string)(unsafe.Pointer(&reportJSON)))
	} else {
		if len(vulnerabilities) > 0 {
			log.Warn().Msgf("[Scanner] Layer [%s] of image [%s] contains %d total vulnerabilities",
				layerID[:8], imageName, len(vulnerabilities))

			vulnerabilities = FilterApproved(vulnerabilities, unapproved, reportAll)
			SortBySeverity(vulnerabilities)

			if len(unapproved) > 0 {
				log.Error().Msgf("[Scanner] Layer [%s] of image [%s] contains %d "+
					"unapproved vulnerabilities", layerID[:8], imageName, len(unapproved))
				PrintTable(vulnerabilities, unapproved)
			} else {
				log.Info().Msgf("[Scanner] Layer [%s] of image [%s] contains NO "+
					"unapproved vulnerabilities", layerID[:8], imageName)
				if reportAll {
					PrintTable(vulnerabilities, unapproved)
				}
			}
		} else {
			log.Info().Msgf("[Scanner] Layer [%s] of image [%s] contains "+
				"NO unapproved vulnerabilities", layerID[:8], imageName)
		}
	}
}

// ReportToFile writes the report to file
func ReportToFile(
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	file string,
	hash string,
) {
	if file == "" {
		return
	}
	report := &VulnerabilityReport{
		Image:           imageName,
		Hash:            hash,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: report is not proper JSON %v", err)
	}
	if err = ioutil.WriteFile(file, reportJSON, 0644); err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: could not write to file %v", err)
	}
}

// ReportToFileOfDividedLayer ...
func ReportToFileOfDividedLayer(
	imageName string,
	vulnerabilitiesGroup []VulnerabilityInfoOfLayer,
	layerFile string,
	file string,
) {
	layerDataBytes, err := ioutil.ReadFile(layerFile)
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not open layer data file: %v", err)
	}
	var layerDataSlice []LayerCommand
	err = json.Unmarshal(layerDataBytes, &layerDataSlice)
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not load layer data: not proper JSON %v", err)
	}
	layerData := make(map[string]string)
	for _, layer := range layerDataSlice {
		layerData[layer.Layer] = layer.Command
	}
	if file == "" {
		return
	}
	var report VulnerabilityLayerGroupReport
	for i, vulnerabilityInfo := range vulnerabilitiesGroup {
		if i == 0 {
			report = append(report,
				VulnerabilityLayerReport{
					vulnerabilityInfo.Layer,
					layerData[vulnerabilityInfo.Layer],
					vulnerabilityInfo.Vulnerabilities,
				},
			)
			continue
		}
		newVulnerabilities := SliceSubtract(vulnerabilityInfo.Vulnerabilities,
			vulnerabilitiesGroup[i-1].Vulnerabilities)
		if len(newVulnerabilities) > 0 {
			report = append(report,
				VulnerabilityLayerReport{
					vulnerabilityInfo.Layer,
					layerData[vulnerabilityInfo.Layer],
					newVulnerabilities,
				},
			)
		}
	}
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: report is not proper JSON %v", err)
	}
	if err = ioutil.WriteFile(file, reportJSON, 0644); err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: could not write to file %v", err)
	}
}

// ReportToFileOfSingleLayer ...
func ReportToFileOfSingleLayer(
	layerID string,
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	file string,
	hash string,
) {
	if file == "" {
		return
	}
	report := &VulnerabilityReportOfSingleLayer{
		Layer:           layerID,
		Image:           imageName,
		Hash:            hash,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: report is not proper JSON %v", err)
	}
	if err = ioutil.WriteFile(file, reportJSON, 0644); err != nil {
		log.Warn().Msgf("[Scanner] Could not create a report: could not write to file %v", err)
	}
}
