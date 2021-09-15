{{/*
Return the proper tensorsec webhook image name
*/}}
{{- define "tensorsec.webhook.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the proper tensorsec certgen image name
*/}}
{{- define "tensorsec.webhook.certgen.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.certgen.image "global" .Values.global) }}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "webhook.fullname" -}}
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
{{- define "webhook.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "webhook.labels" -}}
app: {{ include "webhook.name" . }}
chart: {{ include "webhook.chart" . }}
release: {{ .Release.Name }}
heritage: {{ .Release.Service }}
{{- end -}}

{{/*
Return the appropriate apiVersion for admission.
*/}}
{{- define "admissionregistration.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1" }}
{{- print "admissionregistration.k8s.io/v1" -}}
{{- else -}}
{{- print "admissionregistration.k8s.io/v1beta1" -}}
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for rbac.
*/}}
{{- define "rbac.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "rbac.authorization.k8s.io/v1" }}
{{- print "rbac.authorization.k8s.io/v1" -}}
{{- else -}}
{{- print "rbac.authorization.k8s.io/v1beta1" -}}
{{- end -}}
{{- end -}}
