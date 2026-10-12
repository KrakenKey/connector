#!/bin/sh
# Checks the Azure template package without deploying anything:
#
#   1. the ARM template test toolkit (arm-ttk), which Partner Center also
#      runs, on mainTemplate.json and createUiDefinition.json;
#   2. cloud-init's schema check on the cloud-config the template builds,
#      rendered here with placeholder values.
#
# Uses PowerShell if it is installed, otherwise the PowerShell container
# image; the cloud-init check runs in an Ubuntu 24.04 container. Needs
# git, python3 and Docker.
set -eu

ARM_TTK_COMMIT=0ec9a41a4503e970a0ec8efb0cd08415cc172175
PWSH_IMAGE=mcr.microsoft.com/powershell:latest
UBUNTU_IMAGE=ubuntu:24.04

dir=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/azure-test.XXXXXX")
trap 'rm -rf "$work"' EXIT

# 1. arm-ttk, on a copy of the files that go into the Marketplace package.
mkdir -p "$work/package"
cp "$dir/mainTemplate.json" "$dir/createUiDefinition.json" "$work/package/"
git clone -q https://github.com/Azure/arm-ttk.git "$work/arm-ttk"
git -C "$work/arm-ttk" -c advice.detachedHead=false checkout -q "$ARM_TTK_COMMIT"

cat >"$work/run-arm-ttk.ps1" <<'PS1'
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $args[0] "arm-ttk/arm-ttk.psd1")
$results = Test-AzTemplate -TemplatePath $args[1]
$failed = @($results | Where-Object { -not $_.Passed })
foreach ($r in $results) {
  $status = if ($r.Passed) { "PASS" } else { "FAIL" }
  Write-Output ("{0}  {1}: {2}" -f $status, $r.File.Name, $r.Name)
  foreach ($e in $r.Errors) { Write-Output ("      " + $e.Exception.Message) }
  foreach ($w in $r.Warnings) { Write-Output ("      warning: " + $w.Message) }
}
Write-Output ("{0} passed, {1} failed" -f ($results.Count - $failed.Count), $failed.Count)
if ($failed.Count -gt 0) { exit 1 }
PS1

echo "== arm-ttk"
if command -v pwsh >/dev/null 2>&1; then
	pwsh -NoProfile -File "$work/run-arm-ttk.ps1" "$work/arm-ttk" "$work/package"
else
	docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
		-v "$work:/work:ro" "$PWSH_IMAGE" \
		pwsh -NoProfile -File /work/run-arm-ttk.ps1 /work/arm-ttk /work/package
fi

# 2. cloud-init schema. The values stand in for what main.bicep fills in.
echo "== cloud-init schema"
python3 - "$dir" "$work/user-data.yaml" <<'PY'
import base64
import json
import sys

src, out = sys.argv[1], sys.argv[2]


def b64(text):
    return base64.b64encode(text.encode()).decode()


with open(f"{src}/cloud-init.yaml", encoding="utf-8") as f:
    template = f.read()
with open(f"{src}/bootstrap.sh", encoding="utf-8") as f:
    bootstrap = f.read()
config = {"krakenkey": {"api_url": "https://api.krakenkey.io"}, "certificates": []}
rendered = (
    template.replace("{0}", b64(bootstrap))
    .replace("{1}", b64("kkce_placeholder"))
    .replace("{2}", b64(json.dumps(config)))
)
with open(out, "w", encoding="utf-8") as f:
    f.write(rendered)
PY
docker run --rm -v "$work/user-data.yaml:/user-data.yaml:ro" "$UBUNTU_IMAGE" sh -c '
	apt-get -qq update >/dev/null &&
	DEBIAN_FRONTEND=noninteractive apt-get -qq install -y cloud-init >/dev/null 2>&1 &&
	cloud-init schema --config-file /user-data.yaml --annotate'
