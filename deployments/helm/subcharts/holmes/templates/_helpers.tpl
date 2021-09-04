{{/* vim: set filetype=mustache: */}}
{{/*
Return the daemon image name
*/}}
{{- define "daemon.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.tensorsecDaemon.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.tensorsecDaemon.image.repository "context" $)) -}}
{{- $imageName := .Values.tensorsecDaemon.image.name -}}
{{- $tag := .Values.tensorsecDaemon.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}


{{/*
Expand the name of the chart.
*/}}
{{- define "falco.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "falco.fullname" -}}
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
{{- define "falco.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Use the fullname if the serviceAccount value is not set
*/}}
{{- define "falco.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name -}}
{{- else }}
{{- $name := default .Chart.Name .Values.fullnameOverride -}}
{{- printf "%s-%s" $name .Release.Namespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Return the proper Falco image name
*/}}
{{- define "falco.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.repository "context" $)) -}}
{{- $imageName := .Values.image.name -}}
{{- $tag := .Values.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}

{{/*
Extract the unixSocket's directory path
*/}}
{{- define "falco.unixSocketDir" -}}
{{- if .Values.falco.grpc.unixSocketPath -}}
{{- .Values.falco.grpc.unixSocketPath | trimPrefix "unix://" | dir -}}
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
