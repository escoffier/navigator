{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "palace.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Return the palace image name */}}
{{- define "palace.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}

{{/* Return the init container image name */}}
{{- define "palace.init.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.initContainers.image "global" .Values.global) }}
{{- end -}}
