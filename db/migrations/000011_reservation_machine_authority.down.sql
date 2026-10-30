BEGIN;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM machine_grants WHERE audience='inventory-reservations') THEN
  RAISE EXCEPTION 'reservation grants require reviewed forward recovery';
 END IF;
END $$;
ALTER TABLE machine_grants DROP CONSTRAINT machine_grants_authority_valid;
ALTER TABLE machine_grants ADD CONSTRAINT machine_grants_audience_check CHECK(audience='catalog-stock-references');
ALTER TABLE machine_grants ADD CONSTRAINT machine_grants_permission_check CHECK(permission='catalog.stock-references:read');
COMMIT;
