#!/bin/sh
# Create the data directory, so the connector can be enrolled as its user
# before the service first starts, and reload systemd so it sees the unit.
# The service is not enabled or started here: it needs a config and an
# enrollment first.
#
# On upgrade, a running service is restarted, unless the config pins a
# plugin version the upgrade removed (see restart_after_upgrade). Debian
# packages do that here. RPM runs this before it removes the old package's
# files, so for RPM it is left to posttrans.sh.
set -e

USER_NAME=krakenkey-connector
DATA_DIR=/var/lib/krakenkey-connector
RPM_MARKER=/var/lib/rpm-state/krakenkey-connector/upgraded

# --- The same in postinstall.sh and posttrans.sh: keep both copies equal. ---
CONFIG=/etc/krakenkey-connector/config.yaml
PLUGIN_DIR=/usr/lib/krakenkey-connector/plugins

# pinned_missing prints "<name> <version>" for every plugin the config pins
# to a version that is installed neither in the system plugin directory nor
# under <data_dir>/plugins. Plugins without a version use the installed one
# and plugins with a path are not looked up, so neither is listed. Only the
# usual YAML layouts are understood; anything else lists nothing.
pinned_missing() {
	[ -r "$CONFIG" ] || return 0
	awk -v q="'" '
		function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
		function unq(s) {
			s = trim(s)
			if (length(s) >= 2 && ((substr(s, 1, 1) == "\"" && substr(s, length(s)) == "\"") ||
			    (substr(s, 1, 1) == q && substr(s, length(s)) == q)))
				s = substr(s, 2, length(s) - 2)
			return s
		}
		/^[^ \t#]/ {
			inp = ($0 ~ /^plugins:[ \t]*(#.*)?$/)
			if ($0 ~ /^data_dir:/) { d = $0; sub(/^data_dir:/, "", d); sub(/[ \t]+#.*$/, "", d); datadir = unq(d) }
			next
		}
		!inp || /^[ \t]*(#|$)/ { next }
		{
			line = $0
			sub(/[ \t]+#.*$/, "", line)
			match(line, /^[ \t]*/)
			ind = RLENGTH
			if (pind == "" || ind <= pind) {
				pind = ind
				name = trim(line); sub(/:.*/, "", name); name = unq(name)
				rest = line; sub(/^[^:]*:/, "", rest)
				if (rest ~ /(^|[{, \t])version[ \t]*:/) { v = rest; sub(/.*version[ \t]*:/, "", v); sub(/[,}].*/, "", v); ver[name] = unq(v) }
				if (rest ~ /(^|[{, \t])path[ \t]*:/) path[name] = 1
			} else {
				if (line ~ /^[ \t]*version[ \t]*:/) { v = line; sub(/^[ \t]*version[ \t]*:/, "", v); ver[name] = unq(v) }
				if (line ~ /^[ \t]*path[ \t]*:/) path[name] = 1
			}
		}
		END {
			if (datadir == "") datadir = "/var/lib/krakenkey-connector"
			for (n in ver) if (!(n in path) && ver[n] != "") print n, ver[n], datadir
		}
	' "$CONFIG" | while read -r name version datadir; do
		case "$name$version" in */* | *..*) continue ;; esac
		[ -d "$PLUGIN_DIR/$name/$version" ] && continue
		[ -e "$datadir/plugins/$name/$version/krakenkey-connector-plugin-$name" ] && continue
		echo "$name $version"
	done
}

# restart_after_upgrade restarts a running service, unless the config pins
# a plugin version that the upgrade removed: a restart would then stop the
# plugins it runs, so it is left running and the admin is told what to fix.
restart_after_upgrade() {
	missing=$(pinned_missing)
	if [ -n "$missing" ]; then
		installed=$(/usr/bin/krakenkey-connector version 2>/dev/null || true)
		installed=${installed#krakenkey-connector }
		installed=${installed%% *}
		echo "krakenkey-connector: $CONFIG pins plugin versions that are no longer installed:"
		echo "$missing" | while read -r name version; do echo "  $name $version"; done
		echo "The service was not restarted, so it keeps the plugins it already runs."
		echo "Remove 'version' from these plugins (the connector then uses the installed"
		echo "plugins${installed:+, version $installed}) or set it to the installed version, then run:"
		echo "  sudo systemctl restart krakenkey-connector"
		return 0
	fi
	if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		systemctl try-restart krakenkey-connector.service || true
	fi
}
# --- end of shared part ---

# deb: $1=configure, $2=previously configured version (empty on first install)
# rpm: $1=1 on first install, 2 or more on upgrade
upgrade=0
format=rpm
case "$1" in
	configure)
		format=deb
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
fi

if [ "$upgrade" = 1 ]; then
	if [ "$format" = deb ]; then
		restart_after_upgrade
	else
		mkdir -p "$(dirname "$RPM_MARKER")"
		: >"$RPM_MARKER"
	fi
else
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
fi

exit 0
