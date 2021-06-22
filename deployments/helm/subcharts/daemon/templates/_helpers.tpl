{{/* vim: set filetype=mustache: */}}
{{/*
Return the daemon image name
*/}}
{{- define "daemon.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.repository "context" $)) -}}
{{- $imageName := .Values.image.name -}}
{{- $tag := .Values.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Return the init esListerner image name
*/}}
{{- define "daemon.esListerner.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.extraInitContainers.esListerner.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.extraInitContainers.esListerner.image.repository "context" $)) -}}
{{- $imageName := .Values.extraInitContainers.esListerner.image.name -}}
{{- $tag := .Values.extraInitContainers.esListerner.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Return the init pgListerner image name
*/}}
{{- define "daemon.pgListerner.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.extraInitContainers.pgListerner.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.extraInitContainers.pgListerner.image.repository "context" $)) -}}
{{- $imageName := .Values.extraInitContainers.pgListerner.image.name -}}
{{- $tag := .Values.extraInitContainers.pgListerner.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "daemon.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "daemon.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Use the fullname if the serviceAccount value is not set
*/}}
{{- define "daemon.serviceAccount" -}}
{{- if .Values.serviceAccount }}
{{- .Values.serviceAccount -}}
{{- else }}
{{- $name := default .Chart.Name .Values.fullnameOverride  -}}
{{- printf "%s-%s" $name .Release.Namespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
