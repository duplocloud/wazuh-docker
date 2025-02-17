#!/usr/bin/env bash
# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
set -e

umask 0002

export USER=wazuh-indexer
export INSTALLATION_DIR=/usr/share/wazuh-indexer
export OPENSEARCH_PATH_CONF=${INSTALLATION_DIR}
export JAVA_HOME=${INSTALLATION_DIR}/jdk

# Read discovery.type from opensearch.yml
export DISCOVERY=$(grep -oP "(?<=discovery.type: ).*" ${OPENSEARCH_PATH_CONF}/opensearch.yml)
export CACERT=$(grep -oP "(?<=plugins.security.ssl.transport.pemtrustedcas_filepath: ).*" ${OPENSEARCH_PATH_CONF}/opensearch.yml)
export CERT="${OPENSEARCH_PATH_CONF}/certs/admin.pem"
export KEY="${OPENSEARCH_PATH_CONF}/certs/admin-key.pem"

run_as_other_user_if_needed() {
  if [[ "$(id -u)" == "0" ]]; then
    # If running as root, drop to specified UID and run command
    exec chroot --userspec=1000:0 / "${@}"
  else
    # Either we are running in Openshift with random uid and are a member of the root group
    # or with a custom --user
    exec "${@}"
  fi
}

# Allow user to specify a custom CMD, for example "opensearch" with extra flags or "/bin/bash"
if [[ "$1" != "opensearchwrapper" ]]; then
  if [[ "$(id -u)" == "0" && $(basename "$1") == "opensearch" ]]; then
    # Rewrite CMD args to replace $1 with `opensearch` explicitly
    set -- "opensearch" "${@:2}"
    exec chroot --userspec=1000:0 / "$@"
  else
    exec "$@"
  fi
fi

# Source environment variables from file if *_FILE vars are provided
source /usr/share/wazuh-indexer/bin/opensearch-env-from-file

# ------------------------------------------------------------------------------
# 1. Handle the INDEXER_PASSWORD (for the Security bootstrap) if present
# ------------------------------------------------------------------------------
if [[ -f bin/opensearch-users ]]; then
  # Check for the INDEXER_PASSWORD environment variable to set the bootstrap password for Security.
if [[ -n "$INDEXER_PASSWORD" ]]; then
    [[ -f /usr/share/wazuh-indexer/opensearch.keystore ]] || (run_as_other_user_if_needed opensearch-keystore create)
    if ! (run_as_other_user_if_needed opensearch-keystore has-passwd --silent) ; then
      # keystore is unencrypted
      if ! (run_as_other_user_if_needed opensearch-keystore list | grep -q '^bootstrap.password$'); then
        (run_as_other_user_if_needed echo "$INDEXER_PASSWORD" | opensearch-keystore add -x 'bootstrap.password')
      fi
    else
      # keystore requires password
      if ! (run_as_other_user_if_needed echo "$KEYSTORE_PASSWORD" \
          | opensearch-keystore list | grep -q '^bootstrap.password$') ; then
        COMMANDS="$(printf "%s\n%s" "$KEYSTORE_PASSWORD" "$INDEXER_PASSWORD")"
        (run_as_other_user_if_needed echo "$COMMANDS" | opensearch-keystore add -x 'bootstrap.password')
      fi
    fi
  fi
fi

# ------------------------------------------------------------------------------
# 2. Handle Azure credentials via the OpenSearch Keystore
# ------------------------------------------------------------------------------
# These environment variables (AZURE_ACCOUNT_NAME, AZURE_ACCOUNT_KEY, AZURE_ENDPOINT_SUFFIX)
# should be passed at container runtime or via Docker Compose.
if [[ -n "$AZURE_ACCOUNT_NAME" || -n "$AZURE_ACCOUNT_KEY" || -n "$AZURE_ENDPOINT_SUFFIX" ]]; then
  [[ -f /usr/share/wazuh-indexer/opensearch.keystore ]] || (run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch-keystore create)

  if [[ -n "$AZURE_ACCOUNT_NAME" ]]; then
    echo "$AZURE_ACCOUNT_NAME" | \
      run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch-keystore add \
        azure.client.default.account --stdin --force
  fi

  if [[ -n "$AZURE_ACCOUNT_KEY" ]]; then
    echo "$AZURE_ACCOUNT_KEY" | \
      run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch-keystore add \
        azure.client.default.key --stdin --force
  fi

  # # If you need a custom endpoint suffix (e.g., for GovCloud):
  # if [[ -n "$AZURE_ENDPOINT_SUFFIX" ]]; then
  #   echo "$AZURE_ENDPOINT_SUFFIX" | \
  #     run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch-keystore add \
  #       azure.client.default.endpoint_suffix --stdin --force
  # fi
fi

# ------------------------------------------------------------------------------
# 3. Ownership adjustments if running as root (Openshift scenario, etc.)
# ------------------------------------------------------------------------------
if [[ "$(id -u)" == "0" ]]; then
  if [[ -n "$TAKE_FILE_OWNERSHIP" ]]; then
    chown -R 1000:0 /usr/share/wazuh-indexer/{data,logs}
  fi
fi

# ------------------------------------------------------------------------------
# 4. (Optional) Securityadmin script for single-node mode (currently commented)
# ------------------------------------------------------------------------------
# if [[ "$DISCOVERY" == "single-node" ]] && [[ ! -f "/var/lib/wazuh-indexer/.flag" ]]; then
#   # run securityadmin.sh for single node with CACERT, CERT, and KEY parameters
#   nohup /securityadmin.sh &
#   touch "/var/lib/wazuh-indexer/.flag"
# fi

# Substitute environment variables in opensearch.yml
if [ -f "${OPENSEARCH_PATH_CONF}/opensearch.yml" ]; then
  cp "${OPENSEARCH_PATH_CONF}/opensearch.yml" "${OPENSEARCH_PATH_CONF}/opensearch.yml.template"
  envsubst < "${OPENSEARCH_PATH_CONF}/opensearch.yml.template" > "${OPENSEARCH_PATH_CONF}/opensearch.yml"
fi

# ------------------------------------------------------------------------------
# 5. Finally, start OpenSearch as the wazuh-indexer user
# ------------------------------------------------------------------------------
run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch <<<"$KEYSTORE_PASSWORD"
