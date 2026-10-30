BEGIN;
INSERT INTO identity_permissions(resource,action,description) VALUES
 ('inventory.stock-adjustments','increase','Prepare and post positive stock increases'),
 ('inventory.stock-adjustments','decrease','Prepare and post positive stock decreases'),
 ('inventory.stock-corrections','reverse','Prepare and reverse an eligible whole stock operation')
ON CONFLICT(resource,action) DO NOTHING;
COMMIT;
