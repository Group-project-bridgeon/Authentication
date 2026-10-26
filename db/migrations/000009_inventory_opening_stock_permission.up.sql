BEGIN;
INSERT INTO identity_permissions(resource,action,description) VALUES ('inventory.opening-stock','post','Prepare and post opening stock') ON CONFLICT(resource,action) DO NOTHING;
COMMIT;
