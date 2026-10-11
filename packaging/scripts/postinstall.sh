#!/bin/sh
# Create the data directory, so the connector can be enrolled as its user
# before the service first starts, and reload systemd so it sees the unit.
# The service is not enabled or started here: it needs a config and an
# enrollment first. On upgrade, restart it only if it is already running.
set -e

USER_NAME=krakenkey-connector
DATA_DIR=/var/lib/krakenkey-connector

# deb: $1=configure, $2=previously configured version (empty on first install)
# rpm: $1=1 on first install, 2 or more on upgrade
upgrade=0
case "$1" in
	configure)
		if [ -n "$2" ]; then upgrade=1; fi
		;;
	*)
		if [ "$1" -ge 2 ] 2>/dev/null; then upgrade=1; fi
		;;
esac

# The connector requires its data directory to be owned by its user, with
# mode 0700. An existing directory is left as it is.
if [ ! -e "$DATA_DIR" ]; then
	install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$DATA_DIR"
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	if [ "$upgrade" = 1 ]; then
		systemctl try-restart krakenkey-connector.service || true
	fi
fi

if [ "$upgrade" = 0 ]; then
	cat <<'MSG'
krakenkey-connector installed. Next:
  1. Edit /etc/krakenkey-connector/config.yaml
  2. Enroll as the service user, with the token from the dashboard in a file
     only root and the krakenkey-connector group can read:
       sudo -u krakenkey-connector env KK_ENROLLMENT_TOKEN_FILE=/etc/krakenkey-connector/enrollment-token krakenkey-connector enroll
  3. sudo -u krakenkey-connector krakenkey-connector validate
  4. sudo systemctl enable --now krakenkey-connector
See https://github.com/KrakenKey/connector#running-as-a-service
MSG
elif grep -q '^plugins:' /etc/krakenkey-connector/config.yaml 2>/dev/null; then
	# The included plugins carry the connector's version, and the config
	# names the version it uses.
	version=$(/usr/bin/krakenkey-connector version 2>/dev/null || true)
	version=${version#krakenkey-connector }
	version=${version%% *}
	cat <<MSG
krakenkey-connector upgraded to ${version}. The included plugins now have
version ${version}: change the plugin versions in
/etc/krakenkey-connector/config.yaml to ${version}, then run
  sudo systemctl restart krakenkey-connector
MSG
fi

exit 0
