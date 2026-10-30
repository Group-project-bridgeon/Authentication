-- name: LockMachine :one
SELECT id, enabled FROM machine_identities WHERE id=$1 FOR UPDATE;

-- name: CreateMachine :exec
INSERT INTO machine_identities(id) VALUES ($1);

-- name: SetMachineEnabled :exec
UPDATE machine_identities SET enabled=$2 WHERE id=$1;

-- name: GrantMachine :exec
INSERT INTO machine_grants(machine_id,audience,permission) VALUES ($1,'catalog-stock-references','catalog.stock-references:read') ON CONFLICT DO NOTHING;

-- name: RevokeMachineGrant :exec
DELETE FROM machine_grants WHERE machine_id=$1 AND audience='catalog-stock-references' AND permission='catalog.stock-references:read';

-- name: MachineHasGrant :one
SELECT EXISTS(SELECT 1 FROM machine_grants WHERE machine_id=$1 AND audience='catalog-stock-references' AND permission='catalog.stock-references:read');

-- name: GetMachineCredential :one
SELECT * FROM machine_credentials WHERE machine_id=$1 AND id=$2;

-- name: InsertMachineCredential :exec
INSERT INTO machine_credentials(id,machine_id,secret_hash,created_at,expires_at) VALUES ($1,$2,$3,$4,$5);

-- name: RevokeMachineCredential :execrows
UPDATE machine_credentials SET revoked_at=clock_timestamp() WHERE machine_id=$1 AND id=$2 AND revoked_at IS NULL;

-- name: RetireMachineOverlap :exec
UPDATE machine_credentials AS c SET revoked_at=clock_timestamp() WHERE c.machine_id=$1 AND c.revoked_at IS NULL AND c.id <> (SELECT recent.id FROM machine_credentials AS recent WHERE recent.machine_id=$1 AND recent.revoked_at IS NULL AND recent.expires_at>clock_timestamp() ORDER BY recent.created_at DESC,recent.id DESC LIMIT 1);

-- name: BoundMachineOverlap :exec
UPDATE machine_credentials SET expires_at=LEAST(expires_at,clock_timestamp()+interval '24 hours') WHERE machine_id=$1 AND revoked_at IS NULL;

-- name: MachineClock :one
SELECT clock_timestamp()::timestamptz AS now;

-- All requested, exact grants must be present under the one requested audience.
-- name: MachineHasAuthority :one
SELECT count(*)=cardinality(sqlc.arg(permissions)::text[]) AS granted FROM machine_grants
WHERE machine_id=sqlc.arg(machine_id) AND audience=sqlc.arg(audience)
AND permission=ANY(sqlc.arg(permissions)::text[]);

-- name: GrantMachineAuthority :exec
INSERT INTO machine_grants(machine_id,audience,permission) VALUES($1,$2,$3) ON CONFLICT DO NOTHING;

-- name: RevokeMachineAuthority :exec
DELETE FROM machine_grants WHERE machine_id=$1 AND audience=$2 AND permission=$3;
