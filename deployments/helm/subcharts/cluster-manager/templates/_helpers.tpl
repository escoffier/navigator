{{/*
Return the proper cluster-manager image name
*/}}
{{- define "clusterManager.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}

{{/*
Return the init container image name
*/}}
{{- define "cluster-manager.init.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.init.image "global" .Values.global) }}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cluster-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

