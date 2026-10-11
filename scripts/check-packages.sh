#!/usr/bin/env bash
# Installs a .deb or .rpm built by GoReleaser in a container and checks it:
#   - the connector runs and its version matches the plugin directories,
#   - the system user, the data and config directories and the plugin files
#     have the expected owners and modes,
#   - plugins.lock matches the plugin binaries, and `validate --offline`,
#     run as the service user, finds and starts every plugin through it,
#   - the shipped config.yaml is refused until a certificate is added,
#   - removing (and for .deb, purging) the package cleans up.
#
# Usage: scripts/check-packages.sh IMAGE PACKAGE [PLATFORM]
#   IMAGE     for example debian:12 or rockylinux:9
#   PACKAGE   a .deb or .rpm
#   PLATFORM  the package's platform, default linux/amd64
set -euo pipefail

image=${1:?usage: $0 IMAGE PACKAGE [PLATFORM]}
pkg=${2:?usage: $0 IMAGE PACKAGE [PLATFORM]}
platform=${3:-linux/amd64}
[ -f "$pkg" ] || {
  echo "no such package: $pkg" >&2
  exit 1
}
dir=$(cd "$(dirname "$pkg")" && pwd)
file=$(basename "$pkg")

echo "== $file on $image ($platform)"
docker run --rm -i --platform "$platform" -v "$dir/$file:/tmp/pkg/$file:ro" -e PKG="/tmp/pkg/$file" "$image" bash -s <<'EOF'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
plugin_dir=/usr/lib/krakenkey-connector/plugins
plugins=(aws-acm azure-keyvault azure-appgateway)
user=krakenkey-connector

as_user() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- "$@"
  else
    su -s /bin/sh "$user" -c "$(printf '%q ' "$@")"
  fi
}
mode() { stat -c '%U:%G %a' "$1"; }
expect_mode() {
  local got
  got=$(mode "$1") || fail "$1 is missing"
  [ "$got" = "$2" ] || fail "$1 is $got, want $2"
  echo "$1: $got"
}

case "$PKG" in
  *.deb)
    kind=deb
    env_file=/etc/default/krakenkey-connector
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq "$PKG" >/dev/null
    ;;
  *.rpm)
    kind=rpm
    env_file=/etc/sysconfig/krakenkey-connector
    if command -v dnf >/dev/null 2>&1; then dnf install -y -q "$PKG" >/dev/null; else yum install -y -q "$PKG" >/dev/null; fi
    ;;
  *) fail "not a .deb or .rpm: $PKG" ;;
esac

# runuser is in util-linux, which minimal images such as fedora:40 lack.
if ! command -v runuser >/dev/null 2>&1 && ! command -v su >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then dnf install -y -q util-linux >/dev/null; fi
fi

echo "== version"
out=$(krakenkey-connector version)
echo "$out"
version=$(awk '{print $2}' <<<"$out")
[ -n "$version" ] || fail "no version in '$out'"

echo "== user and directories"
getent passwd "$user" | grep -Eq "^$user:x:[0-9]+:[0-9]+:[^:]*:/var/lib/krakenkey-connector:(/usr/sbin/nologin|/sbin/nologin|/bin/false)$" ||
  fail "unexpected passwd entry: $(getent passwd "$user")"
uid=$(id -u "$user")
[ "$uid" -lt 1000 ] || fail "$user is not a system user (uid $uid)"
expect_mode /var/lib/krakenkey-connector "$user:$user 700"
expect_mode /etc/krakenkey-connector "root:$user 750"
expect_mode /etc/krakenkey-connector/config.yaml "root:$user 640"
expect_mode "$env_file" "root:$user 640"
expect_mode /usr/bin/krakenkey-connector "root:root 755"
expect_mode /usr/lib/systemd/system/krakenkey-connector.service "root:root 644"
expect_mode "$plugin_dir" "root:root 755"
expect_mode "$plugin_dir/plugins.lock" "root:root 644"
for p in "${plugins[@]}"; do
  expect_mode "$plugin_dir/$p" "root:root 755"
  expect_mode "$plugin_dir/$p/$version" "root:root 755"
  expect_mode "$plugin_dir/$p/$version/krakenkey-connector-plugin-$p" "root:root 755"
done
[ "$(stat -c %a /etc/default 2>/dev/null || echo 755)" = 755 ] || fail "/etc/default mode changed"

echo "== plugins.lock"
cat "$plugin_dir/plugins.lock"
[ "$(grep -c . "$plugin_dir/plugins.lock")" -eq "${#plugins[@]}" ] || fail "plugins.lock should list ${#plugins[@]} plugins"
(cd "$plugin_dir" && sha256sum -c plugins.lock) || fail "plugins.lock does not match the binaries"

echo "== the shipped config is refused until it has a certificate"
if out=$(as_user krakenkey-connector validate --offline 2>&1); then
  echo "$out"
  fail "validate accepted the shipped config"
fi
echo "$out"
grep -q "at least one certificate is required" <<<"$out" || fail "unexpected validate error"

echo "== validate --offline as $user"
cfg=/etc/krakenkey-connector/check.yaml
{
  echo "plugins:"
  for p in "${plugins[@]}"; do echo "  $p: { version: \"$version\" }"; done
  cat <<'YAML'
certificates:
  - id: 1
    names: [plugins.example.com]
    targets:
      - { label: noop, plugin: exec, command: [/bin/true] }
YAML
} >"$cfg"
chgrp "$user" "$cfg"
chmod 0640 "$cfg"
out=$(as_user krakenkey-connector validate --offline --config "$cfg" 2>&1) || {
  echo "$out"
  fail "validate --offline failed"
}
echo "$out"
for p in "${plugins[@]}"; do
  grep -qF "  $p $version: $plugin_dir/$p/$version/krakenkey-connector-plugin-$p (system plugin dir)" <<<"$out" ||
    fail "validate did not find $p in the system plugin directory"
done
[ "$(grep -c ', matches plugins.lock$' <<<"$out")" -eq "${#plugins[@]}" ] ||
  fail "validate did not match every plugin against plugins.lock"
rm -f "$cfg"

echo "== $user cannot change the plugins"
as_user sh -c "
  for f in $plugin_dir/plugins.lock $plugin_dir/*/*/krakenkey-connector-plugin-*; do
    if [ -w \"\$f\" ]; then echo \"\$f is writable\"; exit 1; fi
  done
  for d in $plugin_dir $plugin_dir/*/ $plugin_dir/*/*/; do
    if touch \"\$d/.probe\" 2>/dev/null; then echo \"\$d is writable\"; exit 1; fi
  done
" || fail "the plugin directory is writable by $user"

echo "== remove"
echo "# local edit" >>/etc/krakenkey-connector/config.yaml
if [ "$kind" = deb ]; then
  apt-get remove -y -qq krakenkey-connector >/dev/null
else
  if command -v dnf >/dev/null 2>&1; then dnf remove -y -q krakenkey-connector >/dev/null; else yum remove -y -q krakenkey-connector >/dev/null; fi
fi
for f in /usr/bin/krakenkey-connector /usr/lib/krakenkey-connector /usr/lib/systemd/system/krakenkey-connector.service /usr/share/doc/krakenkey-connector; do
  [ ! -e "$f" ] || fail "$f is still there after removal"
done
[ -d /var/lib/krakenkey-connector ] || fail "removal deleted the data directory"
getent passwd "$user" >/dev/null || fail "removal deleted the user"
if [ "$kind" = deb ]; then
  [ -f /etc/krakenkey-connector/config.yaml ] || fail "remove deleted the edited config"
  echo "== purge"
  apt-get purge -y -qq krakenkey-connector >/dev/null
  for f in /etc/krakenkey-connector /etc/default/krakenkey-connector /var/lib/krakenkey-connector; do
    [ ! -e "$f" ] || fail "$f is still there after purge"
  done
  [ -d /etc/default ] || fail "purge removed /etc/default"
else
  [ -f /etc/krakenkey-connector/config.yaml.rpmsave ] || fail "the edited config was not kept as config.yaml.rpmsave"
fi
echo "OK"
EOF
