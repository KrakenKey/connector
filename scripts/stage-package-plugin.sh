#!/bin/sh
# Stages a plugin binary that GoReleaser just built for the .deb and .rpm
# packages, and rewrites the plugins.lock next to it. GoReleaser runs this
# as a post-build hook of each plugin build (see goreleaser.yaml), so the
# packages carry the same binaries as the archives and the image.
#
# Usage: scripts/stage-package-plugin.sh OS ARCH BINARY VERSION
#
# The result, for linux builds only, is
#   dist/packages/linux_<arch>/plugins/<name>/<version>/krakenkey-connector-plugin-<name>
#   dist/packages/linux_<arch>/plugins/plugins.lock
# laid out like the system plugin directory in the container image.
set -eu

os=${1:?usage: $0 OS ARCH BINARY VERSION}
arch=${2:?usage: $0 OS ARCH BINARY VERSION}
bin=${3:?usage: $0 OS ARCH BINARY VERSION}
version=${4:?usage: $0 OS ARCH BINARY VERSION}

# Only Linux gets packages.
[ "$os" = linux ] || exit 0

cd "$(dirname "$0")/.."
file=$(basename "$bin")
case "$file" in
  krakenkey-connector-plugin-?*) name=${file#krakenkey-connector-plugin-} ;;
  *) echo "stage-package-plugin: $bin is not a plugin binary" >&2; exit 1 ;;
esac
case "$version" in
  "" | . | .. | */* | *" "*) echo "stage-package-plugin: bad version '$version'" >&2; exit 1 ;;
esac

root="dist/packages/${os}_${arch}/plugins"
mkdir -p "$root"

# The plugin builds run in parallel, and each rewrites plugins.lock from
# every binary staged so far. A directory lock serializes them, so the last
# rewrite lists all of them.
lock="$root/.staging-lock"
tries=0
until mkdir "$lock" 2>/dev/null; do
  tries=$((tries + 1))
  if [ "$tries" -gt 600 ]; then
    echo "stage-package-plugin: timed out waiting for $lock" >&2
    exit 1
  fi
  sleep 0.1
done
trap 'rmdir "$lock"' EXIT

umask 022
install -d -m 0755 "$root/$name" "$root/$name/$version"
install -m 0755 "$bin" "$root/$name/$version/$file"
(
  cd "$root"
  LC_ALL=C sha256sum -- */*/krakenkey-connector-plugin-* >plugins.lock.tmp
  chmod 0644 plugins.lock.tmp
  mv plugins.lock.tmp plugins.lock
)
