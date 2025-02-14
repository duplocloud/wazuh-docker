# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
# Force the builder stage to use the linux/amd64 platform.
FROM --platform=linux/amd64 ubuntu:focal AS builder

ARG WAZUH_VERSION
ARG WAZUH_TAG_REVISION

RUN apt-get update -y && apt-get install -y curl openssl xz-utils

COPY config/opensearch.yml /
COPY config/config.sh .
COPY config/config.yml .
COPY config/internal_users.yml .
COPY config/roles_mapping.yml .
COPY config/roles.yml .

RUN bash config.sh

################################################################################
# Build stage 1 (the actual Wazuh indexer image):
# Copy wazuh-indexer from stage 0 and add entrypoint.
################################################################################
# Also force the final stage to use linux/amd64.
FROM --platform=linux/amd64 ubuntu:focal

# Install required packages including apache2-utils for htpasswd.
RUN apt-get update -y && apt-get install -y apache2-utils

ENV USER="wazuh-indexer" \
    GROUP="wazuh-indexer" \
    NAME="wazuh-indexer" \
    INSTALL_DIR="/usr/share/wazuh-indexer"

# Set JAVA_HOME and add Java to PATH so the bundled JDK is used.
ENV JAVA_HOME=${INSTALL_DIR}/jdk
ENV PATH=${JAVA_HOME}/bin:$PATH

RUN getent group $GROUP || groupadd -r -g 1000 $GROUP

RUN useradd --system \
            --uid 1000 \
            --no-create-home \
            --home-dir $INSTALL_DIR \
            --gid $GROUP \
            --shell /sbin/nologin \
            --comment "$USER user" \
            $USER

WORKDIR $INSTALL_DIR

COPY config/entrypoint.sh /
COPY config/securityadmin.sh /

RUN chmod 700 /entrypoint.sh && chmod 700 /securityadmin.sh
RUN chown 1000:1000 /*.sh

COPY --from=builder --chown=1000:1000 /debian/wazuh-indexer/usr/share/wazuh-indexer ${INSTALL_DIR}
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/systemd /usr/lib/systemd
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/sysctl.d /usr/lib/sysctl.d
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/tmpfiles.d /usr/lib/tmpfiles.d

RUN chown -R 1000:1000 ${INSTALL_DIR}

RUN mkdir -p /var/lib/wazuh-indexer && chown 1000:1000 /var/lib/wazuh-indexer && \
    mkdir -p ${INSTALL_DIR}/logs && chown 1000:1000 ${INSTALL_DIR}/logs && \
    mkdir -p /run/wazuh-indexer && chown 1000:1000 /run/wazuh-indexer && \
    mkdir -p /var/log/wazuh-indexer && chown 1000:1000 /var/log/wazuh-indexer && \
    chmod 700 ${INSTALL_DIR} && \
    chmod 600 ${INSTALL_DIR}/jvm.options && \
    chmod 600 ${INSTALL_DIR}/opensearch.yml

# Create symlink for the dynamic linker expected by the binaries.
RUN mkdir -p /lib64 && ln -sf /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2

# Install repositories for snapshot management.
RUN /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-s3
RUN /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-azure
RUN /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-gcs

USER wazuh-indexer

COPY config/wazuh_indexer_ssl_certs/ ${INSTALL_DIR}/certs/

# Expose service port.
EXPOSE 9200

ENTRYPOINT ["/entrypoint.sh"]
# Dummy overridable parameter parsed by entrypoint.
CMD ["opensearchwrapper"]
