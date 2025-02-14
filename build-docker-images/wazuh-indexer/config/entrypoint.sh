#!/usr/bin/env bash
# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
set -e

umask 0002

export USER=wazuh-indexer
export INSTALLATION_DIR=/usr/share/wazuh-indexer
export OPENSEARCH_PATH_CONF=${INSTALLATION_DIR}
export JAVA_HOME=${INSTALLATION_DIR}/jdk
export DISCOVERY=$(grep -oP "(?<=discovery.type: ).*" ${OPENSEARCH_PATH_CONF}/opensearch.yml)
export CACERT=$(grep -oP "(?<=plugins.security.ssl.transport.pemtrustedcas_filepath: ).*" ${OPENSEARCH_PATH_CONF}/opensearch.yml)
export CERT="${OPENSEARCH_PATH_CONF}/certs/admin.pem"
export KEY="${OPENSEARCH_PATH_CONF}/certs/admin-key.pem"

run_as_other_user_if_needed() {
  if [[ "$(id -u)" == "0" ]]; then
    # If running as root, drop to UID 1000 and execute the command.
    exec chroot --userspec=1000:0 / "${@}"
  else
    exec "${@}"
  fi
}

# Allow environment variables to be set via _FILE variables.
# (This is also sourced in opensearch-env and is idempotent.)
source /usr/share/wazuh-indexer/bin/opensearch-env-from-file

# === New: Parameterize internal users passwords ===
# The internal_users.yml file (used by the security plugin) is expected at:
INTERNAL_USERS_FILE="${OPENSEARCH_PATH_CONF}/opensearch-security/internal_users.yml"

if [ -f "$INTERNAL_USERS_FILE" ]; then
  # Verify that htpasswd is available for generating bcrypt hashes.
  if ! command -v htpasswd >/dev/null 2>&1; then
    echo "Error: htpasswd command not found. Please ensure apache2-utils is installed." >&2
    exit 1
  fi

#   update_user_password() {
#   local user="$1"
#   # Construct environment variable name (e.g., admin -> ADMIN_PASSWORD)
#   local env_var_name
#   env_var_name="$(echo "$user" | tr '[:lower:]' '[:upper:]')_PASSWORD"
#   local plain_pass="${!env_var_name}"
#   if [ -n "$plain_pass" ]; then
#     # Generate a bcrypt hash using htpasswd.
#     local hash_output
#     hash_output=$(htpasswd -nbB "$user" "$plain_pass")
#     # The output format is: username:hash; extract the hash.
#     local hashed
#     hashed=$(echo "$hash_output" | cut -d: -f2)
#     echo "Updating password for user '$user'."
#     # Updated sed command: use '#' as delimiter instead of '/'
#     sed -i "/^$user:/,/^[^[:space:]]/ s#^\(\s*hash:\s*\).*#\1\"$hashed\"#" "$INTERNAL_USERS_FILE"
#   fi
# }

update_user_password() {
  local user="$1"
  # Construct environment variable name (e.g., admin -> ADMIN_PASSWORD)
  local env_var_name
  env_var_name="$(echo "$user" | tr '[:lower:]' '[:upper:]')_PASSWORD"
  local plain_pass="${!env_var_name}"
  if [ -n "$plain_pass" ]; then
    # Generate a bcrypt hash with cost 12 using htpasswd.
    local hash_output
    hash_output=$(htpasswd -nbB -C 12 "$user" "$plain_pass")
    # Extract the hash portion (the output is: username:hash)
    local hashed
    hashed=$(echo "$hash_output" | cut -d: -f2)
    echo "Updating password for user '$user'."
    # Use '#' as delimiter to avoid conflicts with slashes in the hash.
    sed -i "/^$user:/,/^[^[:space:]]/ s#^\(\s*hash:\s*\).*#\1\"$hashed\"#" "$INTERNAL_USERS_FILE"
  fi
}


  for user in admin kibanaserver kibanaro logstash readall snapshotrestore wazuh_admin wazuh_user; do
    update_user_password "$user"
  done
fi
# === End password parameterization ===

# Allow custom CMD parameters.
if [[ "$1" != "opensearchwrapper" ]]; then
  if [[ "$(id -u)" == "0" && $(basename "$1") == "opensearch" ]]; then
    set -- "opensearch" "${@:2}"
    exec chroot --userspec=1000:0 / "$@"
  else
    exec "$@"
  fi
fi

if [[ -f bin/opensearch-users ]]; then
  # If INDEXER_PASSWORD is provided, set the bootstrap password in the keystore.
  if [[ -n "$INDEXER_PASSWORD" ]]; then
    [[ -f /usr/share/wazuh-indexer/opensearch.keystore ]] || (run_as_other_user_if_needed opensearch-keystore create)
    if ! (run_as_other_user_if_needed opensearch-keystore has-passwd --silent) ; then
      if ! (run_as_other_user_if_needed opensearch-keystore list | grep -q '^bootstrap.password$'); then
        (run_as_other_user_if_needed echo "$INDEXER_PASSWORD" | opensearch-keystore add -x 'bootstrap.password')
      fi
    else
      if ! (run_as_other_user_if_needed echo "$KEYSTORE_PASSWORD" | opensearch-keystore list | grep -q '^bootstrap.password$') ; then
        COMMANDS="$(printf "%s\n%s" "$KEYSTORE_PASSWORD" "$INDEXER_PASSWORD")"
        (run_as_other_user_if_needed echo "$COMMANDS" | opensearch-keystore add -x 'bootstrap.password')
      fi
    fi
  fi
fi

if [[ "$(id -u)" == "0" ]]; then
  if [[ -n "$TAKE_FILE_OWNERSHIP" ]]; then
    chown -R 1000:0 /usr/share/wazuh-indexer/{data,logs}
  fi
fi

# Optionally, you could uncomment the following block to run securityadmin.sh for single-node setups.
# if [[ "$DISCOVERY" == "single-node" ]] && [[ ! -f "/var/lib/wazuh-indexer/.flag" ]]; then
#   nohup /securityadmin.sh &
#   touch "/var/lib/wazuh-indexer/.flag"
# fi

run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch <<<"$KEYSTORE_PASSWORD"
