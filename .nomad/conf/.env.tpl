{{ range $key, $value := (key (printf "ramp-onboarding-ux/%s" (slice (env "NOMAD_JOB_NAME") 19)) | parseJSON) -}}
{{- $key | trimSpace -}}={{- $value | toJSON }}
{{ end -}}
SENTRY_ENVIRONMENT={{ slice (env "NOMAD_JOB_NAME") 19 }}
FLASK_CACHE_TYPE="RedisCache"
FLASK_CACHE_REDIS_URL="unix:///alloc/tmp/redis.sock?password={{ env "NOMAD_ALLOC_ID" }}"
