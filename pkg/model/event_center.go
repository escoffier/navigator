package model

var alertSortableFields = func() map[string]string {
	return map[string]string{
		"timestamp": "timestamp",
		"severity":  "severityInt",
	}
}

func GetDefaultAlertSortableName() string {
	return "timestamp"
}

func GetAlertSortableNames() []string {
	keys := make([]string, len(alertSortableFields()))

	i := 0
	for k := range alertSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

type AlertKind string

const (
	AlertModuleContainerSecurity = "ContainerSecurity"
)
