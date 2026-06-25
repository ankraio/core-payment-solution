#!/usr/bin/env bash
set -euo pipefail

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../deploy/helm/core-payment-solution" && pwd)"
OUTPUT_DIR="${1:-dist}"

mkdir -p "${OUTPUT_DIR}"
helm lint "${CHART_DIR}" \
  --set notifications.slack.webhookUrl='https://hooks.slack.com/services/example' \
  --set secrets.dashboardToken='lint-only'
helm package "${CHART_DIR}" --destination "${OUTPUT_DIR}"
echo "Packaged chart in ${OUTPUT_DIR}/"
