#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 ARTIFACT_DIRECTORY" >&2; exit 2; }
directory="$(realpath "$1")"
mapfile -t disks < <(find "$directory" -maxdepth 1 -type f -name 'ParticleOS-Host_*.raw.zst')
mapfile -t ukis < <(find "$directory" -maxdepth 1 -type f -name 'ParticleOS-Host_*.efi')
mapfile -t manifests < <(find "$directory" -maxdepth 1 -type f -name 'ParticleOS-Host_*.manifest.gz')
[[ ${#disks[@]} -eq 1 && ${#ukis[@]} -eq 1 && ${#manifests[@]} -eq 1 ]]

sbverify --list "${ukis[0]}" | grep -q 'signature certificates'
gzip -t "${manifests[0]}"

scratch="$(mktemp -d /tmp/particleos-artifacts.XXXXXX)"
trap 'rm -rf -- "$scratch"' EXIT
unzstd --stdout "${disks[0]}" >"$scratch/image.raw"
systemd-repart --json=short "$scratch/image.raw" >"$scratch/partitions.json"
python3 - "$scratch/partitions.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
types = [x['type'] for x in p]
for t, n in [('esp', 1), ('usr', 2), ('usr-verity', 2), ('usr-verity-sig', 2), ('root', 1)]:
    assert types.count(t) == n, (t, types)
labels = [x.get('label', '') for x in p]
assert any(x.endswith('_vsig') and x != '_empty' for x in labels), labels
assert labels.count('_empty') == 3, labels
PY

echo 'Signed UKI, manifest, and A/B GPT artifact validation passed.'
