{{/*
Return the faulty image name
*/}}
{{- define "faulty.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.faulty.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the test image name
*/}}
{{- define "test.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.test.image "global" .Values.global) }}
{{- end -}}
