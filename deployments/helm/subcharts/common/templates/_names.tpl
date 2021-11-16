{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "common.names.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "common.names.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "common.names.fullname" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- if .Values.fullnameOverride -}}
{{- printf "%s-%s" $prefixName .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" $prefixName .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}




{{/*
Create a default fully qualified app for cluster-manager.
*/}}
{{- define "common.cluster-manager.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "cluster-manager" .Values.global.defaultNameOverride.clusterManager -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for console.
*/}}
{{- define "common.console.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "console" .Values.global.defaultNameOverride.console -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for elasticsearch.
*/}}
{{- define "common.elasticsearch.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "elasticsearch-master" .Values.global.defaultNameOverride.elasticsearch -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for eventcenter.
Not use prefixName due to GRPC certificatesSecret imageRegistryUsername.
*/}}
{{- define "common.eventcenter.defaultName" -}}
{{- $name := default "eventcenter" .Values.global.defaultNameOverride.eventcenter -}}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for holmes.
*/}}
{{- define "common.holmes.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "holmes" .Values.global.defaultNameOverride.holmes -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for microseg.
*/}}
{{- define "common.microseg.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "microseg" .Values.global.defaultNameOverride.microseg -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for postgresql.
*/}}
{{- define "common.postgresql.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "postgres-postgresql" .Values.global.defaultNameOverride.postgresql -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for pgpool.
*/}}
{{- define "common.pgpool.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "postgres-pgpool" .Values.global.defaultNameOverride.pgpool -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully DSN name for postgresql.
*/}}
{{- define "common.postgresql.DSN" -}}
{{- printf "%s%s%s" "postgres://postgres:password@" (include "common.postgresql.defaultName" .) ":5432/postgres?sslmode=disable" }}
{{- end -}}

{{/*
Create a default fully DSN name for pgpool.
*/}}
{{- define "common.pgpool.DSN" -}}
{{- printf "%s%s%s" "postgres://postgres:password@" (include "common.pgpool.defaultName" .) ":5432/postgres?sslmode=disable" }}
{{- end -}}

{{/*
Create a default fully qualified app for for redis-ha.
*/}}
{{- define "common.redis-ha.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "redis-ha" .Values.global.defaultNameOverride.redis -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully address for redis-ha sentinel.
*/}}
{{- define "common.redis.sentinel.address" -}}
{{- $sentinel := printf "%s-%s" (include "common.redis-ha.defaultName" .) "announce" -}}
{{- print $sentinel "-0:26379," $sentinel "-1:26379," $sentinel "-2:26379" -}}
{{- end -}}

{{/*
Create a default fully qualified app for scanner.
*/}}
{{- define "common.scanner.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "scanner" .Values.global.defaultNameOverride.scanner -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for security-profiles-manager.
*/}}
{{- define "common.security-profiles-manager.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "sec-prof-man" .Values.global.defaultNameOverride.securityProfilesManager -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for stan.
*/}}
{{- define "common.stan.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "stan" .Values.global.defaultNameOverride.stan -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app for webhook.
*/}}
{{- define "common.webhook.defaultName" -}}
{{- $prefixName := default "csec" .Values.global.prefixName -}}
{{- $name := default "webhook" .Values.global.defaultNameOverride.webhook -}}
{{- printf "%s-%s" $prefixName $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

