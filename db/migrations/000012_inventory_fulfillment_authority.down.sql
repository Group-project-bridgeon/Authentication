BEGIN;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM machine_grants WHERE audience='inventory-fulfillment') THEN RAISE EXCEPTION 'fulfillment grants require reviewed forward recovery'; END IF; END $$;
ALTER TABLE machine_grants DROP CONSTRAINT machine_grants_authority_valid;
ALTER TABLE machine_grants ADD CONSTRAINT machine_grants_authority_valid CHECK(
 (audience='catalog-stock-references' AND permission='catalog.stock-references:read') OR
 (audience='inventory-reservations' AND permission IN('inventory.reservations:reserve','inventory.reservations:release','inventory.reservations:consume','inventory.reservations:read')));
-- Retain permission definitions to preserve existing rows/grants, matching prior migrations.
COMMIT;
