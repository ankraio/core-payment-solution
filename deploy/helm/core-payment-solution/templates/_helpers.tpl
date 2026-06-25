{{/*
Expand the name of the chart.
*/}}
{{- define "core-payment-solution.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "core-payment-solution.fullname" -}}
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
Chart labels
*/}}
{{- define "core-payment-solution.labels" -}}
helm.sh/chart: {{ include "core-payment-solution.chart" . }}
{{ include "core-payment-solution.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "core-payment-solution.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "core-payment-solution.selectorLabels" -}}
app.kubernetes.io/name: {{ include "core-payment-solution.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "core-payment-solution.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "core-payment-solution.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Emulator image (shared static image)
*/}}
{{- define "core-payment-solution.image" -}}
{{- $registry := .Values.image.registry -}}
{{- $repository := .Values.image.repository -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Sensor image (CGO/libpcap)
*/}}
{{- define "core-payment-solution.sensorImage" -}}
{{- $registry := .Values.sensorImage.registry -}}
{{- $repository := .Values.sensorImage.repository -}}
{{- $tag := .Values.sensorImage.tag | default .Values.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Collector ingest URL for emulators inside the cluster
*/}}
{{- define "core-payment-solution.collectorURL" -}}
http://{{ include "core-payment-solution.fullname" . }}-collector:{{ .Values.collector.service.ingestPort }}
{{- end }}

{{/*
Secret name for Slack webhook + dashboard token
*/}}
{{- define "core-payment-solution.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "core-payment-solution.fullname" . }}
{{- end }}
{{- end }}

{{/*
Slack webhook secret key
*/}}
{{- define "core-payment-solution.slackSecretKey" -}}
{{- .Values.notifications.slack.existingSecretKey }}
{{- end }}

{{/*
Dashboard token secret key
*/}}
{{- define "core-payment-solution.dashboardSecretKey" -}}
{{- .Values.secrets.existingSecretDashboardKey }}
{{- end }}

{{/*
Per-emulator labels
*/}}
{{- define "core-payment-solution.emulatorLabels" -}}
{{ include "core-payment-solution.labels" .root }}
app.kubernetes.io/component: emulator
app.kubernetes.io/emulator: {{ .name }}
{{- end }}

{{- define "core-payment-solution.emulatorSelectorLabels" -}}
{{ include "core-payment-solution.selectorLabels" .root }}
app.kubernetes.io/component: emulator
app.kubernetes.io/emulator: {{ .name }}
{{- end }}

{{/*
Should this emulator be deployed?
*/}}
{{- define "core-payment-solution.emulatorEnabled" -}}
{{- $emulator := .emulator -}}
{{- $values := .Values -}}
{{- if not $emulator.enabled -}}
false
{{- else if eq (toString $emulator.tier) "2" -}}
{{- $values.tier2.enabled -}}
{{- else -}}
true
{{- end -}}
{{- end }}
