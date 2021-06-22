{{/*
Return the clair image name
*/}}
{{- define "clair.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.repository "context" $)) -}}
{{- $imageName := .Values.image.name -}}
{{- $tag := .Values.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Return the clair init loadSql image name
*/}}
{{- define "clair.init.loadSql.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.init.loadSql.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.init.loadSql.image.repository "context" $)) -}}
{{- $imageName := .Values.init.loadSql.image.name -}}
{{- $tag := .Values.init.loadSql.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Return the clair init waitpg image name
*/}}
{{- define "clair.init.waitpg.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.init.waitpg.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.init.waitpg.image.repository "context" $)) -}}
{{- $imageName := .Values.init.waitpg.image.name -}}
{{- $tag := .Values.init.waitpg.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}


{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "clair.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "clair.fullname" -}}
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
Create a default fully qualified postgresql name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "postgresql.fullname" -}}
{{- printf "%s-%s" .Release.Name "postgresql" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
