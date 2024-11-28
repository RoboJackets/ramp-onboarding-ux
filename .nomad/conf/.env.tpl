{{ range $key, $value := (key (printf "ramp-onboarding-ux/%s" (slice (env "NOMAD_JOB_NAME") 19)) | parseJSON) -}}
{{- $key | trimSpace -}}={{- $value | toJSON }}
{{ end -}}
SENTRY_ENVIRONMENT={{ slice (env "NOMAD_JOB_NAME") 19 }}
FLASK_CACHE_TYPE="RedisCache"
{{- range service "redis" }}
FLASK_CACHE_REDIS_URL="unix://{{- index .ServiceMeta "socket" | trimSpace -}}?db={{- with (key (printf "ramp-onboarding-ux/%s" (slice (env "NOMAD_JOB_NAME") 19)) | parseJSON) -}}{{- index . "FLASK_CACHE_REDIS_DB" -}}{{- end -}}&password={{- key "redis/password" | trimSpace -}}"
{{ end }}
