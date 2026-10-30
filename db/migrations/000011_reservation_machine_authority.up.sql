BEGIN;
ALTER TABLE machine_grants DROP CONSTRAINT machine_grants_audience_check;
ALTER TABLE machine_grants DROP CONSTRAINT machine_grants_permission_check;
ALTER TABLE machine_grants ADD CONSTRAINT machine_grants_authority_valid CHECK (
 (audience='catalog-stock-references' AND permission='catalog.stock-references:read') OR
 (audience='inventory-reservations' AND permission IN ('inventory.reservations:reserve','inventory.reservations:release','inventory.reservations:consume','inventory.reservations:read')));
-- Machine authority only: no human permission/grant or machine provisioning.
COMMIT;
