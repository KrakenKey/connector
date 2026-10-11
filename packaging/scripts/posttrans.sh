#!/bin/sh
# RPM only: runs after the whole transaction, when an upgrade has removed
# the old package's files. postinstall.sh leaves a marker on upgrade; this
# then restarts a running service, unless the config pins a plugin version
# the upgrade removed (see restart_after_upgrade).
set -e

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

[ -e "$RPM_MARKER" ] || exit 0
rm -f "$RPM_MARKER"
rmdir "$(dirname "$RPM_MARKER")" 2>/dev/null || true

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
restart_after_upgrade

exit 0
