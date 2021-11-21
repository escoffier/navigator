{{/* vim: set filetype=mustache: */}}
{/*
Return the immune-test image name
*/}}
{{- define "immune-test.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
