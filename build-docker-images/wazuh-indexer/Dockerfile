# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
FROM amazonlinux:2023 AS builder

ARG WAZUH_VERSION
ARG WAZUH_PACKAGES_SOURCE
ARG WAZUH_TAG_REVISION

RUN yum install curl-minimal openssl xz tar findutils shadow-utils -y

COPY config/check_repository.sh /
RUN chmod 775 /check_repository.sh && \
    source /check_repository.sh

RUN yum install wazuh-indexer-${WAZUH_VERSION}-${WAZUH_TAG_REVISION} -y && \
    yum clean all

COPY config/opensearch.yml /

COPY config/config.sh .

COPY config/config.yml /

COPY config/action_groups.yml /

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
FROM amazonlinux:2023

ENV USER="wazuh-indexer" \
    GROUP="wazuh-indexer" \
    NAME="wazuh-indexer" \
    INSTALL_DIR="/usr/share/wazuh-indexer"

RUN yum install curl-minimal shadow-utils findutils hostname -y

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

RUN chmod 700 /entrypoint.sh && chmod 700 /securityadmin.sh && \
    mkdir -p /usr/share/wazuh-indexer && \
    chown 1000:1000 /usr/share/wazuh-indexer && \
    chown 1000:1000 /*.sh

COPY --from=builder --chown=1000:1000 /usr/share/wazuh-indexer /usr/share/wazuh-indexer
COPY --from=builder --chown=1000:1000 /etc/wazuh-indexer /usr/share/wazuh-indexer/config
COPY --from=builder --chown=1000:1000 /debian/wazuh-indexer/usr/share/wazuh-indexer /usr/share/wazuh-indexer
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/systemd /usr/lib/systemd
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/sysctl.d /usr/lib/sysctl.d
COPY --from=builder --chown=0:0 /debian/wazuh-indexer/usr/lib/tmpfiles.d /usr/lib/tmpfiles.d

RUN mkdir -p /var/lib/wazuh-indexer && chown 1000:1000 /var/lib/wazuh-indexer && \
    mkdir -p /usr/share/wazuh-indexer/logs && chown 1000:1000 /usr/share/wazuh-indexer/logs && \
    mkdir -p /run/wazuh-indexer && chown 1000:1000 /run/wazuh-indexer && \
    mkdir -p /var/log/wazuh-indexer && chown 1000:1000 /var/log/wazuh-indexer && \
    chmod 700 /usr/share/wazuh-indexer && \
    chmod 700 /usr/share/wazuh-indexer/config && \
    chmod 600 /usr/share/wazuh-indexer/config/jvm.options && \
    chmod 600 /usr/share/wazuh-indexer/config/opensearch.yml

# DuploCloud: baked TLS certs (same as 4.11.1-audit image), 4.14.x config path
COPY --chown=1000:1000 config/wazuh_indexer_ssl_certs/ /usr/share/wazuh-indexer/config/certs/
RUN chmod 500 /usr/share/wazuh-indexer/config/certs && \
    chmod 400 /usr/share/wazuh-indexer/config/certs/*

USER wazuh-indexer

# DuploCloud: snapshot repository plugins
RUN /entrypoint.sh /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-s3 repository-azure repository-gcs

# DuploCloud: CVE remediation - swap vulnerable bundled jars for fixed same-line
# releases from Maven Central (see config/cve_patch_jars.sh for the exact list)
USER root
COPY config/cve_patch_jars.sh /tmp/cve_patch_jars.sh
RUN bash /tmp/cve_patch_jars.sh /usr/share/wazuh-indexer && rm -f /tmp/cve_patch_jars.sh
USER wazuh-indexer

# Services ports
EXPOSE 9200

ENTRYPOINT ["/entrypoint.sh"]
# Dummy overridable parameter parsed by entrypoint
CMD ["opensearchwrapper"]