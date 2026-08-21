#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

read -r scenario <"$CREDENTIALS_DIRECTORY/update-audit-scenario"
read -r base_version <"$CREDENTIALS_DIRECTORY/update-audit-base-version"
# shellcheck source=/dev/null
source /usr/lib/os-release

[[ $scenario == rollback-denial || $scenario == workload-quarantine ||
   $scenario == host-fallback ]]
[[ $base_version =~ ^[0-9]+([.][0-9]+)*$ ]]
[[ ${IMAGE_VERSION:-} =~ ^[0-9]+([.][0-9]+)*$ ]]

if [[ $scenario == workload-quarantine ]]; then
    echo "UPDATE_ROLLBACK_AUDIT_HEALTH_REJECT version=$IMAGE_VERSION"
    exit 1
fi

echo "UPDATE_ROLLBACK_AUDIT_HEALTH_ACCEPT version=$IMAGE_VERSION"
