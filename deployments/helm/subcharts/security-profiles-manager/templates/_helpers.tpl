{{/* vim: set filetype=mustache: */}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "secProfilesManager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Return the proper certgen image name
*/}}
{{- define "secProfilesManager.certgen.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.global.certgen.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the security-profiles-manager webhook image name
*/}}
{{- define "secProfilesWebhook.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.webhook.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the security-profiles-manager manager image name
*/}}
{{- define "secProfilesManager.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the loader image name
*/}}
{{- define "secProfilesLoader.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.loader.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the audit image name
*/}}
{{- define "secProfilesAudit.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.audit.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the initContainers image name
*/}}
{{- define "initContainers.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.initContainers.image "global" .Values.global) }}
{{- end -}}
