{{/*
Return the proper image name
{{ include "tensorsec.common.images.image" ( dict "imageRoot" .Values.path.to.the.image "global" $) }}
*/}}
{{- define "tensorsec.common.images.image" -}}
{{- $registryName := .imageRoot.registry -}}
{{- $repositoryName := .imageRoot.repository -}}
{{- $imageName := .imageRoot.name -}}
{{- $tag := .imageRoot.tag | toString -}}
{{- if .global }}
    {{- if .global.image.registry }}
     {{- $registryName = .global.image.registry -}}
    {{- end -}}
    {{- if .global.image.repository }}
     {{- $repositoryName = .global.image.repository -}}
    {{- end -}}
{{- end -}}
{{- if (and $registryName $repositoryName) }}
{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- else -}}
{{- printf "%s:%s" $imageName $tag -}}
{{- end -}}
{{- end -}}


{{/*
Return the image path
*/}}
{{- define "tensorsec.common.images.registryPath" -}}
{{- $registryName := .imageRoot.registry -}}
{{- $repositoryName := .imageRoot.repository -}}
{{- if .global }}
    {{- if .global.image.registry }}
     {{- $registryName = .global.image.registry -}}
    {{- end -}}
    {{- if .global.image.repository }}
     {{- $repositoryName = .global.image.repository -}}
    {{- end -}}
{{- end -}}
{{- printf "%s/%s" $registryName $repositoryName -}}
{{- end -}}
