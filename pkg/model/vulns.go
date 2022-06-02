package model

var (
	LanguageMap = map[string]string{
		"bundler":      "ruby",
		"pipenv":       "python",
		"gemfile":      "ruby",
		"pipfile":      "python",
		"poetry":       "python",
		"composer":     "php",
		"package-lock": "node.js",
		"yarn":         "node.js",
		"jar":          "java",
		"war":          "ava",
		"ear":          "java",
		"gobinary":     "go",
		"gemspec":      "ruby",
		"node-pkg":     "node.js",
		"npm":          "node.js",
		"python-pkg":   "python",
		"cargo":        "rust",
		"pom":          "java",
		"nuget":        ".net",
		"pip":          "python",
		"gomod":        "go",
	}
)

func GetVulnLanguageMap() map[string]string {
	return LanguageMap
}

func GetSeverityInt(level string) int {
	switch level {
	case SeverityCritical:
		return SeverityCriticalInt
	case SeverityHigh:
		return SeverityHighInt
	case SeverityMedium:
		return SeverityMediumInt
	case SeverityLow:
		return SeverityLowInt
	case SeverityUnknown:
		return SeverityUnknownInt
	default:
		return SeverityNegligibleInt
	}
}

const (
	SeverityCriticalInt   = 5
	SeverityHighInt       = 4
	SeverityMediumInt     = 3
	SeverityLowInt        = 2
	SeverityUnknownInt    = 1
	SeverityNegligibleInt = 0
	SeverityCritical      = "CRITICAL"
	SeverityHigh          = "HIGH"
	SeverityMedium        = "MEDIUM"
	SeverityLow           = "LOW"
	SeverityNegligible    = "NEGLIGIBLE"
	SeverityUnknown       = "UNKNOWN"

	SeverityCriticalView   = "高危"
	SeverityHighView       = "高"
	SeverityMediumView     = "中"
	SeverityLowView        = "低"
	SeverityNegligibleView = "可忽略"
	SeverityUnknownView    = "未知"
)

func GetSeverity(level int) string {
	switch level {
	case SeverityCriticalInt:
		return SeverityCritical
	case SeverityHighInt:
		return SeverityHigh
	case SeverityMediumInt:
		return SeverityMedium
	case SeverityLowInt:
		return SeverityLow
	case SeverityUnknownInt:
		return SeverityUnknown
	default:
		return SeverityNegligible
	}
}
func GetSeverityView(level int) string {
	switch level {
	case SeverityCriticalInt:
		return SeverityCriticalView
	case SeverityHighInt:
		return SeverityHighView
	case SeverityMediumInt:
		return SeverityMediumView
	case SeverityLowInt:
		return SeverityLowView
	case SeverityUnknownInt:
		return SeverityUnknownView
	default:
		return SeverityNegligibleView
	}
}
