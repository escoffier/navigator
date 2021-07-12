{{/*
Return the driftPrevention image name
*/}}
{{- define "driftPrevention.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.repository "context" $)) -}}
{{- $imageName := .Values.image.name -}}
{{- $tag := .Values.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Return the proper tensorsec certgen image name
*/}}
{{- define "tensorsec.certgen.image" -}}
{{- $registryName := (include "tensorsec.tplVaule" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplVaule" ( dict "value" .Values.image.repository "context" $)) -}}
{{- $imageName := .Values.global.certgen.image.name -}}
{{- $tag := .Values.global.certgen.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "driftPrevention.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "driftPrevention.fullname" -}}
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
{{- define "driftPrevention.serviceAccount" -}}
{{- if .Values.serviceAccount }}
{{- .Values.serviceAccount -}}
{{- else }}
{{- $name := default .Chart.Name .Values.fullnameOverride -}}
{{- printf "%s-%s" $name .Release.Namespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
