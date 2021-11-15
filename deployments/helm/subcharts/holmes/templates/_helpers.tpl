{{/* vim: set filetype=mustache: */}}
{{/*
Return the daemon image name
*/}}
{{- define "daemon.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.daemon.image "global" .Values.global) }}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "falco.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Return the proper Falco image name
*/}}
{{- define "falco.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}

{{/*
Extract the unixSocket's directory path
*/}}
{{- define "falco.unixSocketDir" -}}
{{- if .Values.falco.grpc.unixSocketPath -}}
{{- .Values.falco.grpc.unixSocketPath | trimPrefix "unix://" | dir -}}
{{- end -}}
{{- end -}}
