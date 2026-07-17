{{ range $key, $value := (key (printf "ramp-onboarding-ux/%s" (slice (env "NOMAD_JOB_NAME") 19)) | parseJSON) -}}
{{- $key | trimSpace -}}={{- $value | toJSON }}
{{ end -}}
SENTRY_ENVIRONMENT={{ slice (env "NOMAD_JOB_NAME") 19 }}
FLASK_CACHE_TYPE="RedisCache"
FLASK_CACHE_REDIS_URL="unix:///alloc/tmp/redis.sock?db=0&password={{ env "NOMAD_ALLOC_ID" }}"
FLASK_ORG_CHART_NOTIFY_URL="https://org-chart.robojackets.org/api/import-ramp-user"
FLASK_CELERY_BROKER_URL=redis+socket://:{{ env "NOMAD_ALLOC_ID" }}@/alloc/tmp/redis.sock?virtual_host=1
FLASK_CELERY_RESULT_BACKEND=redis+socket://:{{ env "NOMAD_ALLOC_ID" }}@/alloc/tmp/redis.sock?virtual_host=2
FLASK_APP=ramp_onboarding_ux
FLASK_SESSION_COOKIE_NAME="__Host-ramp_session"
FLASK_SESSION_COOKIE_DOMAIN=false
FLASK_SESSION_COOKIE_HTTPONLY=true
FLASK_SESSION_COOKIE_SECURE=true
FLASK_SESSION_COOKIE_SAMESITE="Lax"
FLASK_PREFERRED_URL_SCHEME="https"
