{{/*
Return the clair image name
*/}}
{{- define "kibana.registryPath" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.repository "context" $)) -}}

{{- printf "%s/%s" $registryName $repositoryName -}}
{{- end -}}


{{/*
Return the kibana image name
*/}}
{{- define "kibana.image" -}}
{{- $registryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.registry "context" $)) -}}
{{- $repositoryName := (include "tensorsec.tplvalues" ( dict "value" .Values.image.repository "context" $)) -}}
{{- $imageName := .Values.image.name -}}
{{- $tag := .Values.image.tag | toString -}}

{{- printf "%s/%s/%s:%s" $registryName $repositoryName $imageName $tag -}}
{{- end -}}