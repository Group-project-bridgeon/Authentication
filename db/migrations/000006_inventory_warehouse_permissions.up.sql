BEGIN;
-- Definitions only; no role or user grants.
INSERT INTO identity_permissions (resource, action, description) VALUES
 ('inventory.warehouses', 'read', 'Inventory warehouses read'),
 ('inventory.warehouses', 'create', 'Inventory warehouses create'),
 ('inventory.warehouses', 'update', 'Inventory warehouses update')
ON CONFLICT (resource, action) DO NOTHING;
COMMIT;
