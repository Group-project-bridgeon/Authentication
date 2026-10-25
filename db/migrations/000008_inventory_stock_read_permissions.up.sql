BEGIN;
-- Approved definitions only. No identities, roles, user grants or machine grants.
INSERT INTO identity_permissions (resource, action, description) VALUES
 ('inventory.stock-balances', 'read', 'Inventory stored stock balances read'),
 ('inventory.stock-movements', 'read', 'Inventory recorded stock movement history read')
ON CONFLICT (resource, action) DO NOTHING;
COMMIT;
