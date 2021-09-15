{{/* vim: set filetype=mustache: */}}

{{/*
Return the scanner image name
*/}}
{{- define "scanner.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{/*
Return the scanner docker registry image name
*/}}
{{- define "scanner.docker.registry.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.dockerregistry.image "global" .Values.global) }}
{{- end -}}
{/*
Return the scanner webshell server image name
*/}}
{{- define "scanner.webshell.server.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.webshell.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the init container image name
*/}}
{{- define "scanner.init.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.init.image "global" .Values.global) }}
{{- end -}}


{{/*
Expand the name of the chart.
*/}}
{{- define "scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "scanner.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "scanner.labels" -}}
app: {{ include "scanner.name" . }}
chart: {{ include "scanner.chart" . }}
release: {{ .Release.Name }}
heritage: {{ .Release.Service }}
{{- end -}}
