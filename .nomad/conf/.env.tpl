{{ range $key, $value := (key (printf "ramp-onboarding-ux/%s" (slice (env "NOMAD_JOB_NAME") 19)) | parseJSON) -}}
{{- $key | trimSpace -}}={{- $value | toJSON }}
{{ end -}}
SENTRY_ENVIRONMENT={{ slice (env "NOMAD_JOB_NAME") 19 }}
