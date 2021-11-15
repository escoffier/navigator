{{/* vim: set filetype=mustache: */}}

{{/*
Return the scanner image name
*/}}
{{- define "scanner.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{/*
Return the scanner docker registry image name
*/}}
{{- define "scanner.docker.registry.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.dockerregistry.image "global" .Values.global) }}
{{- end -}}
{/*
Return the scanner webshell server image name
*/}}
{{- define "scanner.webshell.server.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.webshell.image "global" .Values.global) }}
{{- end -}}
{/*
Return the scanner scan report image name
*/}}
{{- define "scanner.scan-report.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.scanreport.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the init container image name
*/}}
{{- define "scanner.init.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.init.image "global" .Values.global) }}
{{- end -}}


{{/*
Expand the name of the chart.
*/}}
{{- define "scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
