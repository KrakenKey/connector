#!/bin/sh
# Builds the Microsoft Marketplace package for the Azure Application
# (solution template) offer: a zip with mainTemplate.json and
# createUiDefinition.json at its root. main.bicep's modules are compiled
# into mainTemplate.json as nested templates, so there are no other files.
#
#   deploy/azure/package.sh [output.zip]
#
# Default output: dist/azure/krakenkey-connector-azure.zip. Checks first
# that mainTemplate.json matches main.bicep.
set -eu

dir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$dir/../.." && pwd)
out=${1:-"$root/dist/azure/krakenkey-connector-azure.zip"}

"$dir/build.sh" --check

mkdir -p "$(dirname "$out")"
rm -f "$out"
python3 - "$out" "$dir/mainTemplate.json" "$dir/createUiDefinition.json" <<'PY'
import os
import sys
import zipfile

out, *files = sys.argv[1:]
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for path in files:
        # Fixed timestamps, so the same sources give the same zip.
        info = zipfile.ZipInfo(os.path.basename(path), date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(path, "rb") as f:
            z.writestr(info, f.read())
PY
echo "wrote $out"
