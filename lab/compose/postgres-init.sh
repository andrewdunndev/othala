#!/usr/bin/env bash
# Initialize separate kratos and hydra databases + users in a single
# Postgres instance. Runs on first container start (mounted into
# /docker-entrypoint-initdb.d/).

set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER kratos WITH PASSWORD '${KRATOS_PG_PASS}';
    CREATE DATABASE kratos OWNER kratos;
    GRANT ALL PRIVILEGES ON DATABASE kratos TO kratos;

    CREATE USER hydra WITH PASSWORD '${HYDRA_PG_PASS}';
    CREATE DATABASE hydra OWNER hydra;
    GRANT ALL PRIVILEGES ON DATABASE hydra TO hydra;
EOSQL
