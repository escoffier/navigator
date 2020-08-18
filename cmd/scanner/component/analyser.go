package component

import (
	"regexp"

	"github.com/williballenthin/govt"

	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

var (
	// CveWhitelistDb ...
	CveWhitelistDb map[string]struct{}

	// IgnoredSensitiveInDatabaseReg ...
	IgnoredSensitiveInDatabaseReg *regexp.Regexp

	// SensitiveAnalysedFlag ...
	SensitiveAnalysedFlag = redclair.SecretPattern{
		Description: "",
		Type:        "",
		Value:       "",
		Regex:       &regexp.Regexp{},
	}

	// VtClient ...
	VtClient *govt.Client

	// cveWhitelist      map[string]struct{}
	sensitivePatterns []redclair.SecretPattern
)

// GetVtReport ...
func GetVtReport(client *govt.Client, fileHash string) (int, error) {
	r, err := client.GetFileReport(fileHash)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("GetFileReport error")
		return -2, err // Detect error
	}
	return int(r.Positives), nil
}

// VirusAnalyse ...
func VirusAnalyse(targetFile *redclair.TempFileSignature) error {
	//  0 No risk
	// >0 Risk level (larger index means more dangerous)
	// -1 Not analysed
	// -2 Error occurred
	// -3 No need to analyse
	// -4 Only for test

	if targetFile.Dumped {
		log.Warn().
			Str("file", targetFile.Filename).
			Msg("File has been dumped before the analysis of virus.")
	}
	if targetFile.Detected != -1 {
		log.Warn().
			Str("file", targetFile.Filename).
			Msg("File has been analysed of virus for more than 1 times.")
	}

	if len(targetFile.HeadContent) <= 4 {
		targetFile.Detected = -3
		return nil
	}
	if string(targetFile.HeadContent[1:4]) != "ELF" {
		targetFile.Detected = -3
		return nil
	}

	var err error
	targetFile.Detected, err = GetVtReport(VtClient, targetFile.Digest)
	return err
}

// SensitiveInfoAnalyse ...
func SensitiveInfoAnalyse(targetFile *redclair.TempFileSignature) error {
	if targetFile.Dumped {
		log.Warn().
			Str("file", targetFile.Filename).
			Msg("File has been dumped before the analysis of virus.")
	}
	if targetFile.Sensitive != nil {
		log.Warn().
			Str("file", targetFile.Filename).
			Msg("File has been analysed of virus for more than 1 times.")
	}

	targetFile.Sensitive = []redclair.SecretPattern{SensitiveAnalysedFlag}

	for _, p := range sensitivePatterns {
		if p.Type == "Filename" {
			if p.Regex.MatchString(targetFile.Filename) {
				targetFile.Sensitive = append(targetFile.Sensitive, p)
			}
		}
	}
	return nil
}

// DumpToDb ...
func DumpToDb(
	targetFile *redclair.TempFileSignature,
	DbData []interface{},
	image string,
) []interface{} {
	for _, pattern := range targetFile.Sensitive[1:] {
		DbData = append(DbData, redclair.ClairImageFileFlattenedSignature{
			Image:     image,
			Filename:  targetFile.Filename,
			Digest:    targetFile.Digest,
			Size:      targetFile.Size,
			Detected:  targetFile.Detected,
			Sensitive: pattern.Description + " - " + pattern.Value + " - " + pattern.Type,
		})
	}
	targetFile.Dumped = true
	return DbData
}

// DumpToAggregatedDb ...
func DumpToAggregatedDb(
	targetFile *redclair.TempFileSignature,
) (exportData redclair.AggregatedTempFileSignature) {
	var sensitiveTemp []redclair.SecretPattern
	for _, pattern := range targetFile.Sensitive[1:] {
		sensitiveTemp = append(sensitiveTemp, redclair.SecretPattern{
			Description: pattern.Description,
			Type:        pattern.Type,
			Value:       pattern.Value,
			Regex:       &regexp.Regexp{},
		})
	}

	exportData = redclair.AggregatedTempFileSignature{
		Filename:  targetFile.Filename,
		Digest:    targetFile.Digest,
		Size:      targetFile.Size,
		Detected:  targetFile.Detected,
		Sensitive: sensitiveTemp,
	}
	return
}
