#!/bin/sh
# Let systemd forget the removed unit. Removing the package keeps the
# krakenkey-connector user, the config in /etc/krakenkey-connector and the
# keys, identity and state in /var/lib/krakenkey-connector, so a reinstall
# picks up where it left off. Purging the Debian package (apt purge) also
# deletes /var/lib/krakenkey-connector, including the connector's identity
# and private keys; the user is kept.
set -e

# deb: $1=remove, purge, upgrade, ...
# rpm: $1=0 on removal, 1 or more on upgrade
if [ "$1" = purge ]; then
	rm -rf /var/lib/krakenkey-connector
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi

exit 0
