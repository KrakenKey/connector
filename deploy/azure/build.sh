#!/bin/sh
# Compiles main.bicep into mainTemplate.json with a pinned Bicep version.
#
#   deploy/azure/build.sh          write mainTemplate.json
#   deploy/azure/build.sh --check  fail if mainTemplate.json is not what
#                                  main.bicep compiles to
#
# Uses the Azure CLI if it is installed, otherwise the Azure CLI container
# image (needs Docker; set USE_DOCKER=1 to prefer it). Nothing here signs in
# to Azure.
set -eu

BICEP_VERSION=v0.48.1
AZ_IMAGE=mcr.microsoft.com/azure-cli:2.91.0

dir=$(cd "$(dirname "$0")" && pwd)
check=0
case "${1:-}" in
	--check) check=1 ;;
	"") ;;
	*)
		echo "usage: $0 [--check]" >&2
		exit 2
		;;
esac

out="$dir/mainTemplate.json"
if [ "$check" = 1 ]; then
	out=$(mktemp "${TMPDIR:-/tmp}/mainTemplate.XXXXXX")
	trap 'rm -f "$out"' EXIT
fi

# shellcheck disable=SC2016 # $1 to $3 are for the inner shell.
build_cmd='az config set bicep.use_binary_from_path=false bicep.check_version=false >/dev/null 2>&1 &&
	az bicep install --version "$1" >/dev/null &&
	az bicep build --file "$2" --outfile "$3"'

if [ "${USE_DOCKER:-0}" != 1 ] && command -v az >/dev/null 2>&1; then
	# A throwaway Azure CLI config directory, so the pinned Bicep and the
	# settings above do not touch the user's own Azure CLI setup.
	azdir=$(mktemp -d "${TMPDIR:-/tmp}/azure-cli.XXXXXX")
	AZURE_CONFIG_DIR="$azdir" sh -c "$build_cmd" sh "$BICEP_VERSION" "$dir/main.bicep" "$out" || {
		rm -rf "$azdir"
		exit 1
	}
	rm -rf "$azdir"
else
	outdir=$(dirname "$out")
	docker run --rm \
		--user "$(id -u):$(id -g)" \
		-e HOME=/tmp/home \
		-v "$dir:/src:ro" \
		-v "$outdir:/out" \
		"$AZ_IMAGE" \
		sh -c "mkdir -p /tmp/home && $build_cmd" sh "$BICEP_VERSION" /src/main.bicep "/out/$(basename "$out")"
fi

if [ "$check" = 1 ]; then
	if ! diff -u "$dir/mainTemplate.json" "$out"; then
		echo "deploy/azure/mainTemplate.json is out of date. Run 'make azure-template' and commit the result." >&2
		exit 1
	fi
	echo "deploy/azure/mainTemplate.json matches main.bicep"
fi
