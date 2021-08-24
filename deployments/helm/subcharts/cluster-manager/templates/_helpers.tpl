{{/*
Return the proper tensorsec cluster-manager image name
*/}}
{{- define "tensorsec.image" -}}
{{- $registryName := (include "tensorsec.tplVaule" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplVaule" ( dict "value" .Values.image.repository "context" $)) -}}
{{- $imageName := .Values.image.name -}}
{{- $tag := .Values.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "cluster-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cluster-manager.fullname" -}}
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
{{- define "cluster-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "cluster-manager.labels" -}}
app: {{ include "cluster-manager.name" . }}
chart: {{ include "cluster-manager.chart" . }}
release: {{ .Release.Name }}
heritage: {{ .Release.Service }}
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

