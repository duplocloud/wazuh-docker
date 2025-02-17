# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
FROM --platform=linux/amd64 ubuntu:focal AS builder

ARG WAZUH_VERSION
ARG WAZUH_TAG_REVISION

RUN apt-get update -y && apt-get install curl openssl xz-utils -y

COPY config/opensearch.yml /
COPY config/config.sh .
COPY config/config.yml /
COPY config/internal_users.yml /
COPY config/roles_mapping.yml /
COPY config/roles.yml /

RUN bash config.sh

################################################################################
# Build stage 1 (the actual Wazuh indexer image):
#
# Copy wazuh-indexer from stage 0
# Add entrypoint
################################################################################
FROM --platform=linux/amd64 ubuntu:focal

ENV USER="wazuh-indexer" \
    GROUP="wazuh-indexer" \
    NAME="wazuh-indexer" \
    INSTALL_DIR="/usr/share/wazuh-indexer"

# Ensure the 'wazuh' group exists
RUN getent group $GROUP || groupadd -r -g 1000 $GROUP

# Ensure the 'wazuh-indexer' user exists
RUN useradd --system \
            --uid 1000 \
            --no-create-home \
            --home-dir $INSTALL_DIR \
            --gid $GROUP \
            --shell /sbin/nologin \
            --comment "$USER user" \
            $USER
# Install gettext (which provides envsubst)
RUN apt-get update && apt-get install -y gettext && rm -rf /var/lib/apt/lists/*
WORKDIR $INSTALL_DIR

COPY config/entrypoint.sh /
COPY config/securityadmin.sh /

RUN chmod 700 /entrypoint.sh && chmod 700 /securityadmin.sh
RUN chown 1000:1000 /*.sh

COPY --from=builder --chown=1000:1000 /debian/wazuh-indexer/usr/share/wazuh-indexer /usr/share/wazuh-indexer
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/systemd /usr/lib/systemd
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/sysctl.d /usr/lib/sysctl.d
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/tmpfiles.d /usr/lib/tmpfiles.d

RUN chown -R 1000:1000 /usr/share/wazuh-indexer
RUN mkdir -p /etc/wazuh-indexer && chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer
RUN mkdir -p /var/lib/wazuh-indexer && chown 1000:1000 /var/lib/wazuh-indexer && \
    mkdir -p /usr/share/wazuh-indexer/logs && chown 1000:1000 /usr/share/wazuh-indexer/logs && \
    mkdir -p /run/wazuh-indexer && chown 1000:1000 /run/wazuh-indexer && \
    mkdir -p /var/log/wazuh-indexer && chown 1000:1000 /var/log/wazuh-indexer && \
    chmod 700 /usr/share/wazuh-indexer && \
    chmod 600 /usr/share/wazuh-indexer/jvm.options && \
    chmod 600 /usr/share/wazuh-indexer/opensearch.yml

# Install repositories for snapshot management
RUN /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-s3
RUN /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-azure
RUN /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-gcs

USER wazuh-indexer

COPY config/wazuh_indexer_ssl_certs/ /usr/share/wazuh-indexer/certs/

# Services ports
EXPOSE 9200

ENTRYPOINT ["/entrypoint.sh"]
# Dummy overridable parameter parsed by entrypoint
CMD ["opensearchwrapper"]
