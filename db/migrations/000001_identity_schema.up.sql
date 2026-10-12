CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE identity_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(150),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,

    token_version INTEGER NOT NULL DEFAULT 0
        CHECK (token_version >= 0),

    last_login_at TIMESTAMPTZ,

    deactivated_at TIMESTAMPTZ,
    deactivated_by UUID,

    created_by UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT identity_users_email_normalized
        CHECK (email = lower(btrim(email))),

    CONSTRAINT identity_users_deactivation_consistency
        CHECK (
            (is_active = TRUE AND deactivated_at IS NULL)
            OR
            (is_active = FALSE AND deactivated_at IS NOT NULL)
        ),

    CONSTRAINT identity_users_deactivated_by_fk
        FOREIGN KEY (deactivated_by)
        REFERENCES identity_users(id)
);

CREATE UNIQUE INDEX identity_users_email_lower_uq
    ON identity_users (lower(email));

-------------------------------------------------------------------------------------

CREATE TABLE identity_external_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity_users(id),

    provider VARCHAR(50) NOT NULL,
    provider_subject VARCHAR(255) NOT NULL,

    email_at_link VARCHAR(255),

    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,

    CONSTRAINT identity_external_identities_provider_subject_uq
        UNIQUE (provider, provider_subject)
);

CREATE INDEX identity_external_identities_user_id_idx
    ON identity_external_identities(user_id);


-------------------------------------------------------------------------------------

CREATE TABLE identity_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL UNIQUE
        REFERENCES identity_users(id),

    password_hash VARCHAR(255),

    password_changed_at TIMESTAMPTZ,

    failed_login_count INTEGER NOT NULL DEFAULT 0
        CHECK (failed_login_count >= 0),

    locked_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-------------------------------------------------------------------------------------

CREATE TABLE identity_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,

    is_system BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-------------------------------------------------------------------------------------

CREATE TABLE identity_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,

    description TEXT,

    CONSTRAINT identity_permissions_resource_action_uq
        UNIQUE (resource, action)
);

-------------------------------------------------------------------------------------

CREATE TABLE identity_user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity_users(id),

    role_id UUID NOT NULL
        REFERENCES identity_roles(id),

    scope_type VARCHAR(30) NOT NULL DEFAULT 'GLOBAL',
    scope_id UUID,

    assigned_by UUID,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT identity_user_roles_scope_type_ck
        CHECK (scope_type IN ('GLOBAL', 'WAREHOUSE')),

    CONSTRAINT identity_user_roles_scope_consistency_ck
        CHECK (
            (scope_type = 'GLOBAL' AND scope_id IS NULL)
            OR
            (scope_type = 'WAREHOUSE' AND scope_id IS NOT NULL)
        )
);

CREATE UNIQUE INDEX identity_user_roles_assignment_uq
    ON identity_user_roles
    (user_id, role_id, scope_type, scope_id)
    NULLS NOT DISTINCT;

CREATE INDEX identity_user_roles_user_id_idx
    ON identity_user_roles(user_id);

CREATE INDEX identity_user_roles_role_id_idx
    ON identity_user_roles(role_id);


-------------------------------------------------------------------------------------

CREATE TABLE identity_role_permissions (
    role_id UUID NOT NULL
        REFERENCES identity_roles(id),

    permission_id UUID NOT NULL
        REFERENCES identity_permissions(id),

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX identity_role_permissions_permission_id_idx
    ON identity_role_permissions(permission_id);


-------------------------------------------------------------------------------------

CREATE TABLE identity_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity_users(id),

    family_id UUID NOT NULL,

    token_hash BYTEA NOT NULL UNIQUE,

    replaced_by_id UUID
        REFERENCES identity_refresh_tokens(id),

    replaced_at TIMESTAMPTZ,

    user_agent VARCHAR(255),
    ip_address INET,

    expires_at TIMESTAMPTZ NOT NULL,
    family_expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(50),

    last_used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT identity_refresh_tokens_expiry_ck
        CHECK (expires_at <= family_expires_at)
);

CREATE INDEX identity_refresh_tokens_user_id_idx
    ON identity_refresh_tokens(user_id);

CREATE INDEX identity_refresh_tokens_family_id_idx
    ON identity_refresh_tokens(family_id);

CREATE INDEX identity_refresh_tokens_expires_at_idx
    ON identity_refresh_tokens(expires_at);


-------------------------------------------------------------------------------------

CREATE TABLE identity_auth_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID
        REFERENCES identity_users(id),

    email_attempted VARCHAR(255),

    event_type VARCHAR(50) NOT NULL,

    ip_address INET,
    user_agent VARCHAR(255),
    request_id VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX identity_auth_events_user_created_idx
    ON identity_auth_events(user_id, created_at);

CREATE INDEX identity_auth_events_type_created_idx
    ON identity_auth_events(event_type, created_at);

CREATE INDEX identity_auth_events_created_idx
    ON identity_auth_events(created_at);

-----------------------------------------------------------------------
-------------------------------------------------------------------------------------

CREATE TABLE identity_password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity_users(id),

    token_hash BYTEA NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ NOT NULL,

    used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX identity_password_reset_tokens_user_id_idx
    ON identity_password_reset_tokens(user_id);


-------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------

CREATE TABLE identity_email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity_users(id),

    token_hash BYTEA NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ NOT NULL,

    verified_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX identity_email_verification_tokens_user_id_idx
    ON identity_email_verification_tokens(user_id);

-------------------------------------------------------------------------------------