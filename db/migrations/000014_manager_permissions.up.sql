BEGIN;

INSERT INTO identity_permissions (resource, action, description) VALUES
    ('manager.approvals', 'submit', 'Submit resource for manager approval'),
    ('manager.approvals', 'read', 'View approval request status and history'),
    ('manager.approvals', 'approve', 'Approve pending workflow level'),
    ('manager.approvals', 'reject', 'Reject pending workflow'),
    ('manager.rbac', 'manage', 'Create roles and assign/revoke user roles'),
    ('manager.authz', 'check', 'Evaluate role permissions via authz check')
ON CONFLICT (resource, action) DO NOTHING;

COMMIT;
