#!/bin/sh
# Create the krakenkey-connector system user and group before files are
# unpacked, so the config files get the right group.
set -e

USER_NAME=krakenkey-connector
GROUP_NAME=krakenkey-connector
HOME_DIR=/var/lib/krakenkey-connector

if [ -x /usr/sbin/nologin ]; then
	NOLOGIN=/usr/sbin/nologin
elif [ -x /sbin/nologin ]; then
	NOLOGIN=/sbin/nologin
else
	NOLOGIN=/bin/false
fi

if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
	groupadd --system "$GROUP_NAME"
fi

if ! getent passwd "$USER_NAME" >/dev/null 2>&1; then
	useradd --system --gid "$GROUP_NAME" --home-dir "$HOME_DIR" \
		--no-create-home --shell "$NOLOGIN" \
		--comment "KrakenKey Connector" "$USER_NAME"
fi

exit 0
