BEGIN;
ALTER TABLE machine_grants DROP CONSTRAINT machine_grants_authority_valid;
ALTER TABLE machine_grants ADD CONSTRAINT machine_grants_authority_valid CHECK(
 (audience='catalog-stock-references' AND permission='catalog.stock-references:read') OR
 (audience='inventory-reservations' AND permission IN('inventory.reservations:reserve','inventory.reservations:release','inventory.reservations:consume','inventory.reservations:read')) OR
 (audience='inventory-fulfillment' AND permission IN('inventory.dispatches:create','inventory.dispatches:cancel','inventory.dispatches:read')));
INSERT INTO identity_permissions(resource,action,description) VALUES
 ('inventory.dispatches','dispatch','Confirm full reservation dispatch across Sales owners and warehouses'),
 ('inventory.deliveries','update','Record delivery outcomes across Sales owners and warehouses'),
 ('inventory.dispatches','read','Read dispatches across Sales owners and warehouses') ON CONFLICT(resource,action) DO NOTHING;
-- Definitions only; no human grants or machine provisioning.
COMMIT;
