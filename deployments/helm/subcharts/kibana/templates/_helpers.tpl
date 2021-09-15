{{/*
Return the clair image name
*/}}
{{- define "kibana.registryPath" -}}
{{ include "tensorsec.common.images.registryPath" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}


{{/*
Return the kibana image name
*/}}
{{- define "kibana.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the kibana initContainer image name
*/}}
{{- define "kibana.init.image" -}}
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.init.image "global" .Values.global) }}
{{- end -}}
