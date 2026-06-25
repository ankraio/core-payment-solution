#!/usr/bin/env bash
# Restrict container egress to the Slack webhook host only.
#
# Docker Compose cannot enforce per-container egress, so this is the operator's
# responsibility on the Linux host. This script installs nftables rules that
# allow DNS + outbound HTTPS to Slack's webhook host and drop everything else
# leaving the Docker bridge. Run as root on the deployment host. Review before
# use; adjust the bridge interface and Slack address range for your environment.
set -euo pipefail

BRIDGE_INTERFACE="${BRIDGE_INTERFACE:-docker0}"
SLACK_HOST="${SLACK_HOST:-hooks.slack.com}"

if ! command -v nft >/dev/null 2>&1; then
	echo "nftables (nft) is required" >&2
	exit 1
fi

SLACK_IPS="$(getent ahostsv4 "${SLACK_HOST}" | awk '{print $1}' | sort -u | paste -sd, -)"
if [[ -z "${SLACK_IPS}" ]]; then
	echo "could not resolve ${SLACK_HOST}" >&2
	exit 1
fi

echo "Allowing egress only to ${SLACK_HOST} (${SLACK_IPS}) from ${BRIDGE_INTERFACE}"

nft -f - <<NFT
table inet honeypot_egress {
	chain forward {
		type filter hook forward priority 0; policy accept;
		iifname "${BRIDGE_INTERFACE}" udp dport 53 accept
		iifname "${BRIDGE_INTERFACE}" tcp dport 53 accept
		iifname "${BRIDGE_INTERFACE}" ip daddr { ${SLACK_IPS} } tcp dport 443 accept
		iifname "${BRIDGE_INTERFACE}" ct state established,related accept
		iifname "${BRIDGE_INTERFACE}" drop
	}
}
NFT

echo "Egress lockdown installed. Remove with: nft delete table inet honeypot_egress"
