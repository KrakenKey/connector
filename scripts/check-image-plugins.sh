#!/usr/bin/env bash
# Checks the plugins in a connector image built by GoReleaser:
#   - plugins.lock matches the binaries in the image,
#   - those binaries are the ones GoReleaser built (dist/),
#   - `validate --offline` finds every plugin in the system plugin directory
#     and starts it as the image's user, with and without plugin versions in
#     the config,
#   - that user cannot change the plugin directory.
#
# Usage: scripts/check-image-plugins.sh IMAGE VERSION [DIST_DIR]
#   IMAGE    a linux/amd64 image, such as ghcr.io/krakenkey/connector:v1.2.3-amd64
#   VERSION  the connector version, without the leading v
#   DIST_DIR GoReleaser's output directory (default: dist)
set -euo pipefail

image=${1:?usage: $0 IMAGE VERSION [DIST_DIR]}
version=${2:?usage: $0 IMAGE VERSION [DIST_DIR]}
dist=${3:-dist}
plugin_dir=/usr/lib/krakenkey-connector/plugins
plugins=(aws-acm azure-keyvault azure-appgateway)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

echo "== plugins.lock in $image"
lock=$(docker run --rm --entrypoint cat "$image" "$plugin_dir/plugins.lock")
echo "$lock"
docker run --rm --entrypoint sh "$image" -c "cd $plugin_dir && sha256sum -c plugins.lock" ||
  fail "plugins.lock does not match the binaries in the image"

echo "== lock entries against $dist"
[ "$(grep -c . <<<"$lock")" -eq "${#plugins[@]}" ] || fail "plugins.lock should list exactly ${#plugins[@]} plugins"
for p in "${plugins[@]}"; do
  bin=krakenkey-connector-plugin-$p
  built=$(find "$dist" -path "*/plugin-${p}_linux_amd64*/$bin" -type f | head -n 1)
  [ -n "$built" ] || fail "no linux/amd64 build of $p in $dist"
  want=$(sha256sum "$built" | cut -d' ' -f1)
  grep -qx "$want  $p/$version/$bin" <<<"$lock" || fail "plugins.lock has no entry '$want  $p/$version/$bin'"
  echo "$p/$version/$bin: $want"
done

echo "== validate --offline as the image's user"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
{
  echo "plugins:"
  for p in "${plugins[@]}"; do echo "  $p: { version: \"$version\" }"; done
  cat <<'EOF'
certificates:
  - id: 1
    names: [plugins.example.com]
    targets:
      - { label: noop, plugin: exec, command: [/bin/true] }
EOF
} >"$work/config.yaml"
chmod 0644 "$work/config.yaml"
out=$(docker run --rm -v "$work/config.yaml:/etc/krakenkey-connector/config.yaml:ro" "$image" \
  validate --offline --config /etc/krakenkey-connector/config.yaml) || {
  echo "$out"
  fail "validate --offline failed"
}
echo "$out"
for p in "${plugins[@]}"; do
  bin=krakenkey-connector-plugin-$p
  grep -qF "  $p $version: $plugin_dir/$p/$version/$bin (system plugin dir)" <<<"$out" ||
    fail "validate did not find $p in the system plugin directory"
done
[ "$(grep -c ', matches plugins.lock$' <<<"$out")" -eq "${#plugins[@]}" ] ||
  fail "validate did not match every plugin against plugins.lock"

echo "== validate --offline with the plugins declared without a version"
{
  echo "plugins:"
  for p in "${plugins[@]}"; do echo "  $p: {}"; done
  sed -n '/^certificates:/,$p' "$work/config.yaml"
} >"$work/bundled.yaml"
chmod 0644 "$work/bundled.yaml"
out=$(docker run --rm -v "$work/bundled.yaml:/etc/krakenkey-connector/config.yaml:ro" "$image" \
  validate --offline --config /etc/krakenkey-connector/config.yaml) || {
  echo "$out"
  fail "validate --offline failed without plugin versions"
}
echo "$out"
for p in "${plugins[@]}"; do
  bin=krakenkey-connector-plugin-$p
  grep -qF "  $p $version (bundled, version not set): $plugin_dir/$p/$version/$bin (system plugin dir)" <<<"$out" ||
    fail "validate did not use the bundled $p"
done

echo "== the image's user cannot change the plugins"
docker run --rm --entrypoint sh "$image" -c "
  set -u
  [ \"\$(id -u)\" = 10001 ] || { echo \"runs as uid \$(id -u), not 10001\"; exit 1; }
  for f in $plugin_dir/plugins.lock $plugin_dir/*/*/krakenkey-connector-plugin-*; do
    if [ -w \"\$f\" ] || (: >>\"\$f\") 2>/dev/null; then echo \"\$f is writable\"; exit 1; fi
  done
  for d in $plugin_dir $plugin_dir/*/ $plugin_dir/*/*/; do
    if touch \"\$d/.probe\" 2>/dev/null; then echo \"\$d is writable\"; exit 1; fi
  done
  echo 'uid 10001: plugins.lock, binaries and directories are read-only'
" || fail "the plugin directory is writable by the image's user"

echo "OK"
