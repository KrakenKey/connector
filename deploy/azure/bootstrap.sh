#!/bin/bash
# Sets up the KrakenKey connector on a VM created by the Azure template
# (deploy/azure). cloud-init runs it once, as root, on the first boot. It:
#
#   1. adds the signed apt repository at packages.krakenkey.io, after
#      checking the signing key's fingerprint, and installs the connector;
#   2. writes /etc/krakenkey-connector/config.yaml from the template's
#      settings, and tells the Azure plugins to use the VM's managed identity;
#   3. lets unattended-upgrades upgrade the connector from that repository;
#   4. checks the config, enrolls the connector as its service user with
#      the one-time enrollment token, and deletes the token;
#   5. waits for the connector's Azure role assignments to work (they are
#      created after the VM, and take a few minutes to apply), then enables
#      and starts the service.
#
# Output goes to /var/log/cloud-init-output.log. The enrollment token is
# never printed or put on a command line.
set -euo pipefail
umask 077

STATE_DIR=/var/lib/krakenkey-azure
TOKEN_STAGED="$STATE_DIR/enrollment-token"
CONFIG_JSON="$STATE_DIR/config.json"
ETC_DIR=/etc/krakenkey-connector
CONFIG="$ETC_DIR/config.yaml"
TOKEN_FILE="$ETC_DIR/enrollment-token"
ENV_FILE=/etc/default/krakenkey-connector
DATA_DIR=/var/lib/krakenkey-connector
SERVICE_USER=krakenkey-connector
KEYRING_URL=https://packages.krakenkey.io/keys/krakenkey-archive-keyring.deb
# The repository's signing key, as published in the connector README.
KEY_FINGERPRINT=386E25582384DD74692A4EE9F7BA53A4E94FA5DA
# How long to wait for the role assignments to work, and how often to check.
VALIDATE_TIMEOUT=1800
VALIDATE_DELAY=30

export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -q -y -o DPkg::Lock::Timeout=600)

log() { echo "krakenkey-bootstrap: $*"; }

work=""
cleanup() {
	rm -f "$TOKEN_STAGED" "$TOKEN_FILE"
	if [ -n "$work" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT

# retry runs a command up to 10 times with growing delays, for network
# hiccups during the first boot.
retry() {
	local n=1
	until "$@"; do
		if [ "$n" -ge 10 ]; then return 1; fi
		sleep $((n * 6))
		n=$((n + 1))
	done
}

# as_connector runs the connector as its service user, with the service's
# environment file loaded the way systemd loads it for the service.
as_connector() {
	# shellcheck disable=SC2016 # $0 and $@ are for the inner shell.
	runuser -u "$SERVICE_USER" -- sh -c 'set -a; . "$0"; exec krakenkey-connector "$@"' "$ENV_FILE" "$@"
}

chmod 0700 "$STATE_DIR"

if [ -e "$STATE_DIR/done" ]; then
	log "already set up; nothing to do"
	exit 0
fi

# 1. Repository and package.
work=$(mktemp -d)
log "adding the packages.krakenkey.io apt repository"
retry curl -fsSL --proto '=https' --tlsv1.2 -o "$work/keyring.deb" "$KEYRING_URL"
dpkg-deb -x "$work/keyring.deb" "$work/keyring"
fingerprint=$(gpg --batch --no-default-keyring --with-colons --show-keys \
	"$work/keyring/usr/share/keyrings/krakenkey.gpg" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
if [ "$fingerprint" != "$KEY_FINGERPRINT" ]; then
	log "the keyring package has signing key '$fingerprint', expected $KEY_FINGERPRINT; stopping"
	exit 1
fi
retry "${APT[@]}" install "$work/keyring.deb"
retry "${APT[@]}" update
log "installing krakenkey-connector"
retry "${APT[@]}" install krakenkey-connector
krakenkey-connector version

# 2. Config and environment.
log "writing $CONFIG"
python3 - "$CONFIG_JSON" >"$work/config.yaml" <<'PY'
import json
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as f:
    config = json.load(f)
print("# Written by the KrakenKey connector Azure template on the first boot.")
print("# Edit it as described in https://github.com/KrakenKey/connector#configuration,")
print("# check it with:")
print("#   sudo -u krakenkey-connector sh -c 'set -a; . /etc/default/krakenkey-connector; exec krakenkey-connector validate'")
print("# then run: sudo systemctl restart krakenkey-connector")
print()
yaml.safe_dump(config, sys.stdout, sort_keys=False, default_flow_style=False)
PY
install -m 0640 -o root -g "$SERVICE_USER" "$work/config.yaml" "$CONFIG"

# The Azure plugins use the VM's system-assigned managed identity.
if ! grep -q '^AZURE_TOKEN_CREDENTIALS=' "$ENV_FILE"; then
	printf '\n# Set by the Azure template: use the VM'"'"'s managed identity.\nAZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential\n' >>"$ENV_FILE"
fi

# 3. Unattended upgrades. Ubuntu's unattended-upgrades only takes Ubuntu's
# own security updates by default; this adds the KrakenKey repository. The
# connector's config files are edited here, so dpkg is told to keep them
# on upgrades instead of asking (unattended-upgrades skips packages that
# would ask). The package restarts the service after an upgrade.
log "enabling unattended upgrades for krakenkey-connector"
cat >/etc/apt/apt.conf.d/52krakenkey-connector <<'APTCONF'
// Written by the KrakenKey connector Azure template.
// Upgrade the connector from packages.krakenkey.io automatically.
Unattended-Upgrade::Origins-Pattern {
	"origin=KrakenKey,label=KrakenKey,suite=stable";
};
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
// Keep edited config files (such as /etc/krakenkey-connector/config.yaml)
// on upgrades instead of prompting.
Dpkg::Options {
	"--force-confdef";
	"--force-confold";
};
APTCONF
chmod 0644 /etc/apt/apt.conf.d/52krakenkey-connector

# 4. Check the config, then enroll.
log "checking the config"
offline_status=0
offline_output=$(as_connector validate --offline 2>&1) || offline_status=$?
echo "$offline_output"
if grep -q '^Config .*: INVALID' <<<"$offline_output"; then
	log "the config is invalid; not enrolling. Fix $CONFIG, then enroll by hand with a new token (see deploy/azure/README.md)"
	exit 1
fi
if [ "$offline_status" -ne 0 ]; then
	log "validate --offline reported problems; the role assignments may not be in effect yet, continuing"
fi

if [ -e "$DATA_DIR/identity" ]; then
	log "the connector is already enrolled"
else
	log "enrolling the connector"
	install -m 0640 -o root -g "$SERVICE_USER" "$TOKEN_STAGED" "$TOKEN_FILE"
	rm -f "$TOKEN_STAGED"
	enroll_status=0
	runuser -u "$SERVICE_USER" -- env KK_ENROLLMENT_TOKEN_FILE="$TOKEN_FILE" \
		krakenkey-connector enroll || enroll_status=$?
	rm -f "$TOKEN_FILE"
	if [ "$enroll_status" -ne 0 ]; then
		log "enrollment failed (exit code $enroll_status); create a new enrollment token and enroll by hand (see deploy/azure/README.md)"
		exit 1
	fi
fi
rm -f "$TOKEN_STAGED" "$TOKEN_FILE"

# 5. Wait for the role assignments, then start the service.
log "waiting for the connector's Azure permissions (up to $((VALIDATE_TIMEOUT / 60)) minutes)"
validated=0
deadline=$((SECONDS + VALIDATE_TIMEOUT))
while :; do
	status=0
	output=$(as_connector validate 2>&1) || status=$?
	if [ "$status" -eq 0 ]; then
		echo "$output"
		validated=1
		break
	fi
	if [ "$SECONDS" -ge "$deadline" ]; then
		echo "$output"
		break
	fi
	sleep "$VALIDATE_DELAY"
done
if [ "$validated" -eq 1 ]; then
	log "validate passed"
else
	log "validate still reports problems (above); starting the service anyway, it retries on its own"
fi

systemctl enable --now krakenkey-connector.service
touch "$STATE_DIR/done"
log "done: the connector is running (journalctl -u krakenkey-connector)"
