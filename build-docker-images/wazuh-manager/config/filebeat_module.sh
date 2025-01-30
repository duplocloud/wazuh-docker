#!/bin/bash

# Define the default repository
REPOSITORY="packages.wazuh.com/4.x"

# Fetch the latest Wazuh version from GitHub
WAZUH_CURRENT_VERSION=$(curl --silent https://api.github.com/repos/wazuh/wazuh/releases/latest | grep '\"tag_name\":' | sed -E 's/.*\"([^\"]+)\".*/\1/' | cut -c 2-)

# Extract version components
MAJOR_BUILD=$(echo "$WAZUH_VERSION" | cut -d. -f1)
MID_BUILD=$(echo "$WAZUH_VERSION" | cut -d. -f2)
MINOR_BUILD=$(echo "$WAZUH_VERSION" | cut -d. -f3)
MAJOR_CURRENT=$(echo "$WAZUH_CURRENT_VERSION" | cut -d. -f1)
MID_CURRENT=$(echo "$WAZUH_CURRENT_VERSION" | cut -d. -f2)
MINOR_CURRENT=$(echo "$WAZUH_CURRENT_VERSION" | cut -d. -f3)

# Select repository based on version comparison
if [ "$MAJOR_BUILD" -gt "$MAJOR_CURRENT" ]; then
  REPOSITORY="packages-dev.wazuh.com/pre-release"
elif [ "$MAJOR_BUILD" -eq "$MAJOR_CURRENT" ]; then
  if [ "$MID_BUILD" -gt "$MID_CURRENT" ]; then
    REPOSITORY="packages-dev.wazuh.com/pre-release"
  elif [ "$MID_BUILD" -eq "$MID_CURRENT" ]; then
    if [ "$MINOR_BUILD" -gt "$MINOR_CURRENT" ]; then
      REPOSITORY="packages-dev.wazuh.com/pre-release"
    fi
  fi
fi

# Detect system architecture (amd64 or arm64)
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" == "arm64" ]; then
  FILEBEAT_ARCH="arm64"
else
  FILEBEAT_ARCH="amd64"
fi

# Download and install the correct Filebeat package
curl -L -O "https://artifacts.elastic.co/downloads/beats/filebeat/${FILEBEAT_CHANNEL}-${FILEBEAT_VERSION}-${FILEBEAT_ARCH}.deb"
dpkg -i "${FILEBEAT_CHANNEL}-${FILEBEAT_VERSION}-${FILEBEAT_ARCH}.deb"
rm -f "${FILEBEAT_CHANNEL}-${FILEBEAT_VERSION}-${FILEBEAT_ARCH}.deb"

# Ensure the Filebeat module directory exists before extraction
mkdir -p /usr/share/filebeat/module

# Extract Filebeat modules
curl -s https://duplo-wazuh.s3.us-west-2.amazonaws.com/duplo-wazuh-filebeat.tar.gz | tar -xvz -C /usr/share/filebeat/module

# Set correct ownership and permissions
chown -R root:root /usr/share/filebeat/module
chmod -R go-w /usr/share/filebeat/module
