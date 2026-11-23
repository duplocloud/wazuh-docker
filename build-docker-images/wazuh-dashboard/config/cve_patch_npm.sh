#!/bin/bash
# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
#
# CVE remediation: surgically replace specific vendored node_modules copies
# with same-major-version fixed releases downloaded from the npm registry.
# This is a targeted file swap, NOT "npm install" - it never invokes a
# dependency resolver, so it cannot drift or rewrite unrelated packages.
#
# Each entry is: <package>|<currently-installed-version-to-match>|<target-fixed-version>
# Only copies whose on-disk version matches <currently-installed-version-to-match>
# are touched; already-clean copies of the same package name at other versions
# are left alone. The build fails if an expected vulnerable copy can't be found,
# so a future Wazuh version bump that changes the vendored tree doesn't silently
# skip a patch.
set -euo pipefail

INSTALL_DIR="${1:-/usr/share/wazuh-dashboard}"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

PATCHES=(
  "handlebars|4.7.9|4.7.10"
  "proxy-addr|2.0.7|2.0.8"
  "tar|7.5.16|7.5.21"
  "node-forge|1.4.0|1.4.1"
  "follow-redirects|1.16.0|1.16.2"
  "form-data|4.0.5|4.0.6"
  "fast-uri|3.1.0|3.1.7"
  "js-yaml|4.1.1|4.3.2"
  "ip-address|10.2.0|10.3.1"
  "@hapi/content|6.0.2|6.0.3"
  "@modelcontextprotocol/sdk|1.27.1|1.32.0"
  "decode-uri-component|0.2.2|0.5.1"
  "brace-expansion|1.1.15|1.1.20"
  "brace-expansion|2.1.1|2.1.6"
  "axios|1.18.1|1.20.0"
  "body-parser|2.2.2|2.4.0"
)

for entry in "${PATCHES[@]}"; do
  IFS='|' read -r pkg from_ver to_ver <<< "$entry"
  basename_pkg="${pkg##*/}"
  extract_dir="$WORKDIR/extract-${basename_pkg}-${to_ver}"

  if [ ! -d "$extract_dir" ]; then
    tarball="$WORKDIR/${basename_pkg}-${to_ver}.tgz"
    curl -fsSL -o "$tarball" "https://registry.npmjs.org/${pkg}/-/${basename_pkg}-${to_ver}.tgz"
    mkdir -p "$extract_dir"
    tar xzf "$tarball" -C "$extract_dir"
    rm -f "$tarball"
  fi

  mapfile -t dirs < <(find "$INSTALL_DIR" -type d -path "*/node_modules/${pkg}")

  matched=0
  for dir in "${dirs[@]}"; do
    installed=$(grep -m1 '"version"' "$dir/package.json" | sed -E 's/.*"version": *"([^"]+)".*/\1/')
    if [ "$installed" = "$from_ver" ]; then
      matched=$((matched + 1))
      find "$dir" -mindepth 1 -maxdepth 1 ! -name node_modules -exec rm -rf {} +
      cp -a "$extract_dir/package/." "$dir/"
    fi
  done

  if [ "$matched" -eq 0 ]; then
    echo "ERROR: expected to find at least one node_modules copy of ${pkg}@${from_ver} under ${INSTALL_DIR}, found none" >&2
    exit 1
  fi
  echo "Patched ${matched} copy(ies) of ${pkg}: ${from_ver} -> ${to_ver}"
done
