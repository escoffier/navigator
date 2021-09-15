{{/*
Return the faulty image name
*/}}
{{- define "tensorsec.faulty.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.faulty.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the test image name
*/}}
{{- define "tensorsec.test.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.test.image "global" .Values.global) }}
{{- end -}}
