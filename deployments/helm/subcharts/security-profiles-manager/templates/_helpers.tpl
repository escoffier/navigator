{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "secProfilesManager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "secProfilesManager.fullname" -}}
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
{{- define "secProfilesManager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "secProfilesManager.labels" -}}
app: {{ include "secProfilesManager.name" . }}
chart: {{ include "secProfilesManager.chart" . }}
release: {{ .Release.Name }}
heritage: {{ .Release.Service }}
{{- end -}}

{{- define "secProfilesManager.serviceAccount" -}}
{{- if .Values.serviceAccount }}
{{- .Values.serviceAccount -}}
{{- else }}
{{- $name := default .Chart.Name .Values.fullnameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}


{{/*
Return the proper tensorsec certgen image name
*/}}
{{- define "tensorsec.secProfilesManager.certgen.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.global.certgen.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the security-profiles-manager webhook image name
*/}}
{{- define "secProfilesWebhook.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.webhook.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the security-profiles-manager manager image name
*/}}
{{- define "secProfilesManager.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the eventProcessor image name
*/}}
{{- define "eventProcessor.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.eventProcessor.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the loader image name
*/}}
{{- define "secProfilesLoader.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.loader.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the scanner image name
*/}}
{{- define "secProfilesAudit.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.audit.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the scanner image name
*/}}
{{- define "initContainers.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.initContainers.image "global" .Values.global) }}
{{- end -}}
