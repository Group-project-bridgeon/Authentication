BEGIN;
CREATE TABLE machine_identities (
 id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
 enabled boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE machine_grants (
 machine_id uuid NOT NULL REFERENCES machine_identities(id) ON DELETE RESTRICT,
 audience text NOT NULL CHECK (audience = 'catalog-stock-references'),
 permission text NOT NULL CHECK (permission = 'catalog.stock-references:read'),
 PRIMARY KEY(machine_id,audience,permission)
);
CREATE TABLE machine_credentials (
 id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
 machine_id uuid NOT NULL REFERENCES machine_identities(id) ON DELETE RESTRICT,
 secret_hash bytea NOT NULL CHECK (octet_length(secret_hash)=32),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK (expires_at > created_at AND expires_at <= created_at + interval '2160 hours')
);
CREATE INDEX machine_credentials_owner ON machine_credentials(machine_id);
COMMIT;
