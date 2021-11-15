{{/*
Return the proper webhook image name
*/}}
{{- define "webhook.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the proper certgen image name
*/}}
{{- define "webhook.certgen.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.global.certgen.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the proper sidecar image name
*/}}
{{- define "webhook.sidecar.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.sidecar.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the proper sidecar-init image name
*/}}
{{- define "webhook.sidecar.init.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.sidecar.init.image "global" .Values.global) }}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "webhook.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
