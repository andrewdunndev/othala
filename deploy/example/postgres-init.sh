#!/usr/bin/env bash
# Creates the kratos and hydra roles and databases the rendered DSNs name, on first start only.

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
