#!/usr/bin/env bash
# Initialize separate kratos and hydra databases + users in a single
# Postgres instance. Runs on first container start (mounted into
# /docker-entrypoint-initdb.d/).
#
# uuid-ossp extension: Hydra v25.4 release notes flagged this as a
# prerequisite for the Postgres backend. Phase 3 ran clean without it
# (postgres:18-alpine may auto-enable in some setups), but enabling
# defensively avoids a silent "Hydra migrate fails on
# `uuid_generate_v4 does not exist`" bring-up gotcha on fresh databases.
# iac vendors this script verbatim — production gets the same defensive
# enable.

set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER kratos WITH PASSWORD '${KRATOS_PG_PASS}';
    CREATE DATABASE kratos OWNER kratos;
    GRANT ALL PRIVILEGES ON DATABASE kratos TO kratos;

    CREATE USER hydra WITH PASSWORD '${HYDRA_PG_PASS}';
    CREATE DATABASE hydra OWNER hydra;
    GRANT ALL PRIVILEGES ON DATABASE hydra TO hydra;
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname=kratos <<-EOSQL
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOSQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname=hydra <<-EOSQL
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOSQL
