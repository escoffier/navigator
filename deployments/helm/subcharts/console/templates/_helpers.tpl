{{/* vim: set filetype=mustache: */}}
{{/*
Return the console image path
*/}}
{{- define "console.registryPath" -}}
{{ include "common.images.registryPath" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}

{{/*
Return the console image name
*/}}
{{- define "console.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}
{{/*
Return the console image name
*/}}
{{- define "console.init.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.init.image "global" .Values.global) }}
{{- end -}}

{{/* JOBS IMAGE DEFINE */}}
{{/* Return the job cleaner image name */}}
{{- define "jobs.cleaner.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.jobs.Cleaner.image "global" .Values.global) }}
{{- end -}}
{{/* Return the job hunter image name */}}
{{- define "jobs.hunter.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.jobs.Hunter.image "global" .Values.global) }}
{{- end -}}
{{/* Return the job hunter-origin image name */}}
{{- define "jobs.hunter.originImage" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.jobs.HunterOrigin.image "global" .Values.global) }}
{{- end -}}
{{/* Return the job apiscan image name */}}
{{- define "jobs.apiscan.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.jobs.ApiScan.image "global" .Values.global) }}
{{- end -}}
{{/* Return the job platform report image name */}}
{{- define "jobs.platform.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.jobs.Platform.image "global" .Values.global) }}
{{- end -}}

{{- define "console.genImagePullSecret" }}
{{- with .Values.imagePullSecret }}
{{- printf "{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"auth\":\"%s\"}}}" .imageRegistryURL .imageRegistryUsername .imageRegistryPassword (printf "%s:%s" .imageRegistryUsername .imageRegistryPassword | b64enc) | b64enc }}
{{- end }}
{{- end }}
