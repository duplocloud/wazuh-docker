docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh-indexer-data \
           $2_wazuh-indexer-data

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_api_configuration \
           $2_wazuh_api_configuration

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_etc \
           $2_wazuh_etc

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_logs \
           $2_wazuh_logs

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_queue \
           $2_wazuh-queue

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_var_multigroups \
           $2_wazuh-var-multigroups

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_integrations \
           $2_wazuh_integrations

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_active_response \
           $2_wazuh_active_response

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_agentless \
           $2_wazuh_agentless

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=wazuh_wodles \
           $2_wazuh_wodles

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=filebeat_etc \
           $2_filebeat_etc

docker volume create \
           --label com.docker.compose.project=$2 \
           --label com.docker.compose.version=$1 \
           --label com.docker.compose.volume=filebeat_var \
           $2_filebeat_var

docker container run --rm -it \
           -v wazuh4_filebeat_var:/from \
           -v $2_filebeat_var:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_elastic-data:/from \
           -v $2_wazuh-indexer-data:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_api_configuration:/from \
           -v $2_wazuh_api_configuration:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_etc:/from \
           -v $2_wazuh_etc:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_logs:/from \
           -v $2_wazuh_logs:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_queue:/from \
           -v $2_wazuh_queue:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_var_multigroups:/from \
           -v $2_wazuh_var_multigroups:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_integrations:/from \
           -v $2_wazuh_integrations:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_active_response:/from \
           -v $2_wazuh_active_response:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_agentless:/from \
           -v $2_wazuh_agentless:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_ossec_wodles:/from \
           -v $2_wazuh_wodles:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_filebeat_etc:/from \
           -v $2_filebeat_etc:/to \
           alpine ash -c "cd /from ; cp -avp . /to"

docker container run --rm -it \
           -v wazuh4_filebeat_var:/from \
           -v $2_filebeat_var:/to \
           alpine ash -c "cd /from ; cp -avp . /to"