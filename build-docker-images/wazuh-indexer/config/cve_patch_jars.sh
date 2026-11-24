#!/bin/bash
# DuploCloud CVE remediation for the Wazuh indexer image.
#
# Replaces vulnerable jars bundled with wazuh-indexer (OpenSearch core, its
# plugins and the repository-s3/azure/gcs plugins we add) with fixed releases
# from Maven Central. Only patch/minor releases inside the same major line are
# used, and whole library families move together (all netty 4.1.x jars, all
# jline jars, bcprov+bcpkix+bcutil, guava+failureaccess) so no directory ends
# up with mixed versions of one library.
#
# Each entry: <maven groupId>|<artifactId or glob>|<from version>|<to version>
# A glob (e.g. netty-*) matches every jar of that group at <from version>.
# Every download is verified against the Maven Central .sha1 file.
# The build FAILS if an entry matches no jar, so a future Wazuh bump that
# changes the bundled versions can't silently skip a fix (update the list).
set -euo pipefail

ROOT="${1:-/usr/share/wazuh-indexer}"
MAVEN="https://repo1.maven.org/maven2"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

PATCHES=(
  # netty 4.1.135 -> 4.1.137 (CVE fixes in codec, codec-http, codec-http2, handler)
  "io.netty|netty-*|4.1.135.Final|4.1.137.Final"
  # jackson
  "com.fasterxml.jackson.core|jackson-core|2.18.8|2.18.11"
  "com.fasterxml.jackson.core|jackson-databind|2.18.8|2.18.11"
  "com.fasterxml.jackson.core|jackson-databind|2.18.2|2.18.11"
  "com.fasterxml.jackson.core|jackson-databind|2.14.1|2.18.11"
  "com.fasterxml.jackson.core|jackson-annotations|2.14.1|2.18.11"
  "com.fasterxml.jackson.dataformat|jackson-dataformat-cbor|2.18.8|2.18.11"
  "com.fasterxml.jackson.dataformat|jackson-dataformat-smile|2.18.8|2.18.11"
  "com.fasterxml.jackson.dataformat|jackson-dataformat-yaml|2.18.8|2.18.11"
  # guava (+ failureaccess 1.0.3 required by guava 33.7.x)
  "com.google.guava|guava|32.1.3-jre|33.7.2-jre"
  "com.google.guava|guava|33.2.1-jre|33.7.2-jre"
  "com.google.guava|guava|33.4.0-jre|33.7.2-jre"
  "com.google.guava|failureaccess|1.0.1|1.0.3"
  "com.google.guava|failureaccess|1.0.2|1.0.3"
  # bouncycastle
  "org.bouncycastle|bcprov-jdk18on|1.84|1.85"
  "org.bouncycastle|bcpkix-jdk18on|1.84|1.85"
  "org.bouncycastle|bcprov-jdk15to18|1.84|1.85"
  "org.bouncycastle|bcprov-jdk15to18|1.79|1.85"
  "org.bouncycastle|bcpkix-jdk15to18|1.79|1.85"
  "org.bouncycastle|bcutil-jdk15to18|1.79|1.85"
  "org.bouncycastle|bc-fips|2.1.2|2.1.3"
  # opensearch-ml
  "org.apache.httpcomponents.core5|httpcore5|5.3.1|5.4.3"
  "org.apache.httpcomponents.core5|httpcore5-h2|5.3.1|5.4.3"
  "org.jline|jline-*|3.27.1|3.30.15"
  # opensearch-reports-scheduler
  "org.jsoup|jsoup|1.15.3|1.23.2"
  # opensearch-security
  "org.xerial.snappy|snappy-java|1.1.10.7|1.1.10.9"
  "at.yawk.lz4|lz4-java|1.10.1|1.11.4"
)

fetch() { # group artifact version -> path of sha1-verified jar in WORKDIR
  local g="$1" a="$2" v="$3" out="$WORKDIR/$2-$3.jar" url want have
  if [ ! -f "$out" ]; then
    url="$MAVEN/${g//.//}/$a/$v/$a-$v.jar"
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 -o "$out" "$url"
    want=$(curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 "$url.sha1" | cut -c1-40)
    have=$(sha1sum "$out" | cut -c1-40)
    if [ "$want" != "$have" ]; then
      echo "ERROR: sha1 mismatch for $url" >&2; exit 1
    fi
  fi
  echo "$out"
}

for entry in "${PATCHES[@]}"; do
  IFS='|' read -r group pattern from to <<< "$entry"
  mapfile -t jars < <(find "$ROOT" -type f -name "${pattern}-${from}.jar" | sort)
  if [ "${#jars[@]}" -eq 0 ]; then
    echo "ERROR: no jar matching ${pattern}-${from}.jar under $ROOT ($group)" >&2
    exit 1
  fi
  for jar in "${jars[@]}"; do
    file=$(basename "$jar")
    artifact="${file%-"${from}".jar}"
    src=$(fetch "$group" "$artifact" "$to")
    dest="$(dirname "$jar")/${artifact}-${to}.jar"
    cp "$src" "$dest"
    chown --reference="$jar" "$dest"
    chmod --reference="$jar" "$dest"
    rm -f "$jar"
    echo "Patched ${jar#"$ROOT"/}: ${from} -> ${to}"
  done
done
