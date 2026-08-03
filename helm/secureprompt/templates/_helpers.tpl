{{/*
Expand the name of the chart.
*/}}
{{- define "secureprompt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "secureprompt.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "secureprompt.labels" -}}
helm.sh/chart: {{ include "secureprompt.name" . }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "secureprompt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
WS1-P0 DB ROLE SPLIT — the schema-migration initContainer.

WHY AN initContainer AND NOT THE API's OWN BOOT
-----------------------------------------------
`sqlx::migrate!` needs CREATE ON SCHEMA public and table ownership (measured —
018/021/023 fail without CREATE, 022 fails with `must be owner of table
token_vault_entries`). The serving role must have neither, because NOBYPASSRLS
is the only kind of role row-level security applies to, and because FORCE ROW
LEVEL SECURITY filters a table's OWNER rather than exempting it. One connection
cannot hold both sets of rights.

Running it here means the owner credential is mounted into a container that
exits before anything listens. The `api` and `worker` containers themselves
receive only `database-url`, which now names the runtime role.

WHY NOT A HELM HOOK JOB
-----------------------
A `pre-upgrade` Job would also work, but needs a delete-policy, its own
failure-visibility story, and does not protect a pod that is rescheduled later.
An initContainer re-runs on every pod start, is idempotent, and makes
"container did not start" the failure mode rather than "container started
against the wrong schema".

CONCURRENCY: sqlx 0.8.6 sets `locking: true` by default (sqlx-core
migrate/migrator.rs:53), so several replicas' initContainers serialise on a
Postgres advisory lock rather than racing. The tracking-table bootstrap path
around it is `CREATE TABLE IF NOT EXISTS` plus `INSERT ... ON CONFLICT DO
NOTHING`, which is idempotent independently of that lock.
*/}}
{{- define "secureprompt.dbMigrateInitContainer" -}}
- name: db-migrate
  image: "{{ .Values.global.imageRegistry | default "" }}{{ .Values.api.image.repository }}:{{ .Values.api.image.tag }}"
  imagePullPolicy: {{ .Values.api.image.pullPolicy }}
  args: ["--migrate-only"]
  env:
    # The OWNER/MIGRATOR role. Mounted ONLY here.
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: {{ include "secureprompt.fullname" . }}-secrets
          key: migration-database-url
    # Set on the runtime role by this step, and the same value `database-url`
    # is built from in secrets.yaml — so the role and the URL cannot disagree.
    - name: SECUREPROMPT_APP_DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: {{ include "secureprompt.fullname" . }}-secrets
          key: app-db-password
    - name: LOG_LEVEL
      value: {{ .Values.api.env.logLevel | quote }}
  resources:
    requests: { cpu: "50m", memory: "64Mi" }
    limits:   { cpu: "500m", memory: "256Mi" }
{{- end }}
