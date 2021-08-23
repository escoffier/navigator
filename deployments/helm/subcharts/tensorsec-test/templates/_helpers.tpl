{{- define "tensorsec.faulty.image" -}}
{{- $registryName := .Values.faulty.image.regsitry -}}
{{- $repositoryName := .Values.faulty.image.repository -}}
{{- $imageName := .Values.faulty.image.name -}}
{{- $tag := .Values.faulty.image.tag | toString -}}
{{- if .global }}
    {{- if .global.image.regsitry }}
     {{- $registryName = .global.image.regsitry -}}
    {{- end -}}
    {{- if .global.image.repository }}
     {{- $repositoryName = .global.image.repository -}}
    {{- end -}}
{{- end -}}
{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}


{{- define "tensorsec.test.image" -}}
{{- $registryName := .Values.test.image.regsitry -}}
{{- $repositoryName := .Values.test.image.repository -}}
{{- $imageName := .Values.test.image.name -}}
{{- $tag := .Values.test.image.tag | toString -}}
{{- if .global }}
    {{- if .global.image.regsitry }}
     {{- $registryName = .global.image.regsitry -}}
    {{- end -}}
    {{- if .global.image.repository }}
     {{- $repositoryName = .global.image.repository -}}
    {{- end -}}
{{- end -}}
{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}
