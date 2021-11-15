{{/* vim: set filetype=mustache: */}}
{/*
Return the safenode image name
*/}}
{{- define "safenode.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
