{{/*
Renders a value that contains template.
Usage:
{{ include "tensorsec.tplValue" ( dict "value" .Values.path.to.the.Value "context" $) }}
*/}}
{{- define "tensorsec.tplVaule" -}}
  {{- if typeIs "string" .value }}
    {{- tpl .value .context }}
  {{- else }}
    {{- tpl (.value | toYaml ) .context }}
  {{- end}}
{{- end -}}