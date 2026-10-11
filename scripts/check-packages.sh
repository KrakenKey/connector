#!/usr/bin/env bash
# Installs a .deb or .rpm built by GoReleaser in a container and checks it:
#   - the connector runs and its version matches the plugin directories,
#   - the system user, the data and config directories and the plugin files
#     have the expected owners and modes,
#   - plugins.lock matches the plugin binaries, those are the binaries
#     GoReleaser built (when the package sits in GoReleaser's dist
#     directory), and `validate --offline`, run as the service user, finds
#     and starts every plugin through it,
#   - the shipped config.yaml is refused until a certificate is added,
#   - removing (and for .deb, purging) the package cleans up.
#
# With OLD_PACKAGE, an older build of the same package, it first checks an
# upgrade from it in a separate container:
#   - with the plugins declared without a version, the upgrade prints no
#     warning and `validate --offline` uses the new plugins,
#   - with the plugins pinned to the old version, the upgrade names them
#     and says the service was not restarted.
#
# Usage: scripts/check-packages.sh IMAGE PACKAGE [PLATFORM [OLD_PACKAGE]]
#   IMAGE        for example debian:12 or rockylinux:9
#   PACKAGE      a .deb or .rpm
#   PLATFORM     the package's platform, default linux/amd64
#   OLD_PACKAGE  an older .deb or .rpm of the same format and platform
set -euo pipefail

usage="usage: $0 IMAGE PACKAGE [PLATFORM [OLD_PACKAGE]]"
image=${1:?$usage}
pkg=${2:?$usage}
platform=${3:-linux/amd64}
old=${4:-}
for f in "$pkg" ${old:+"$old"}; do
  [ -f "$f" ] || {
    echo "no such package: $f" >&2
    exit 1
  }
done
dir=$(cd "$(dirname "$pkg")" && pwd)
file=$(basename "$pkg")

if [ -n "$old" ]; then
  old_dir=$(cd "$(dirname "$old")" && pwd)
  old_file=$(basename "$old")
  echo "== upgrade from $old_file to $file on $image ($platform)"
  docker run --rm -i --platform "$platform" -v "$dir/$file:/pkg/new/$file:ro" -v "$old_dir/$old_file:/pkg/old/$old_file:ro" \
    -e NEW="/pkg/new/$file" -e OLD="/pkg/old/$old_file" "$image" bash -s <<'EOF'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
plugins=(aws-acm azure-keyvault azure-appgateway)
plugin_dir=/usr/lib/krakenkey-connector/plugins
user=krakenkey-connector
cfg=/etc/krakenkey-connector/config.yaml

# runuser is in util-linux, which minimal images such as fedora:40 lack.
if command -v dnf >/dev/null 2>&1 && ! command -v runuser >/dev/null 2>&1; then
  dnf install -y -q util-linux >/dev/null
fi
# install_pkg installs, upgrades or downgrades to the package $1 and prints
# what the package scripts say.
install_pkg() {
  case "$1" in
    *.deb)
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades "$1" 2>&1 |
        grep -v -e '^debconf' -e '^(Reading' -e '^Preparing' -e '^Unpacking' -e '^Selecting' -e '^Setting up' || true
      ;;
    *.rpm)
      # Not quiet: dnf -q hides what the scriptlets print.
      if [ "$1" = "$OLD" ] && rpm -q krakenkey-connector >/dev/null 2>&1; then
        dnf downgrade -y "$1"
      else
        dnf install -y "$1"
      fi
      ;;
  esac
}
version() { krakenkey-connector version | awk '{print $2}'; }
# write_config writes a config with the three plugins, pinned to version $1
# or, with "", without a version.
write_config() {
  {
    echo "plugins:"
    for p in "${plugins[@]}"; do
      if [ -n "$1" ]; then echo "  $p: { version: \"$1\" }"; else echo "  $p: {}"; fi
    done
    cat <<'YAML'
certificates:
  - id: 1
    names: [plugins.example.com]
    targets:
      - { label: noop, plugin: exec, command: [/bin/true] }
YAML
  } >"$cfg"
}

echo "== plugins without a version"
install_pkg "$OLD" >/dev/null
old_version=$(version)
write_config ""
out=$(install_pkg "$NEW")
echo "$out"
new_version=$(version)
[ "$old_version" != "$new_version" ] || fail "OLD and NEW are both $new_version"
[ ! -e "$plugin_dir/aws-acm/$old_version" ] || fail "the upgrade left $old_version behind"
if grep -q "no longer installed" <<<"$out"; then fail "the upgrade warned about plugins without a version"; fi
out=$(runuser -u "$user" -- krakenkey-connector validate --offline 2>&1) || {
  echo "$out"
  fail "validate --offline failed after the upgrade"
}
for p in "${plugins[@]}"; do
  grep -qF "  $p $new_version (bundled, version not set): $plugin_dir/$p/$new_version/krakenkey-connector-plugin-$p (system plugin dir)" <<<"$out" ||
    { echo "$out"; fail "validate did not use the new bundled $p"; }
done
echo "validate uses the bundled $new_version plugins"

echo "== plugins pinned to the old version"
install_pkg "$OLD" >/dev/null
[ "$(version)" = "$old_version" ] || fail "the downgrade to $old_version failed"
write_config "$old_version"
out=$(install_pkg "$NEW")
echo "$out"
for p in "${plugins[@]}"; do
  grep -qF "  $p $old_version" <<<"$out" || fail "the upgrade did not name $p $old_version"
done
grep -q "The service was not restarted" <<<"$out" || fail "the upgrade did not say the service was left running"
echo "OK"
EOF
fi

echo "== $file on $image ($platform)"
docker run --rm -i --platform "$platform" -v "$dir:/dist:ro" -e PKG="/dist/$file" -e ARCH="${platform#linux/}" "$image" bash -s <<'EOF'
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
for p in "${plugins[@]}"; do
  bin=krakenkey-connector-plugin-$p
  built=
  for f in /dist/plugin-"${p}"_linux_"${ARCH}"*/"$bin"; do
    if [ -f "$f" ]; then built=$f; break; fi
  done
  if [ -z "$built" ]; then
    echo "no GoReleaser build of $p for $ARCH next to the package; not compared"
    continue
  fi
  [ "$(sha256sum <"$built")" = "$(sha256sum <"$plugin_dir/$p/$version/$bin")" ] ||
    fail "$p differs from the GoReleaser build $built"
  echo "$p: same binary as ${built#/dist/}"
done

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
