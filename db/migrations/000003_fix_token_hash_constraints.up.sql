ALTER TABLE identity_email_verification_tokens
    DROP CONSTRAINT IF EXISTS identity_email_verification_tokens_token_hash_key;

ALTER TABLE identity_password_reset_tokens
    DROP CONSTRAINT IF EXISTS identity_password_reset_tokens_token_hash_key;

ALTER TABLE identity_email_verification_tokens
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE identity_password_reset_tokens
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS identity_email_verification_tokens_lookup_idx
    ON identity_email_verification_tokens (user_id, verified_at, expires_at);

CREATE INDEX IF NOT EXISTS identity_password_reset_tokens_lookup_idx
    ON identity_password_reset_tokens (user_id, used_at, expires_at);
