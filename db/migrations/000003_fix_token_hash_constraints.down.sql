DROP INDEX IF EXISTS identity_password_reset_tokens_lookup_idx;
DROP INDEX IF EXISTS identity_email_verification_tokens_lookup_idx;

ALTER TABLE identity_password_reset_tokens
    DROP COLUMN IF EXISTS attempt_count;

ALTER TABLE identity_email_verification_tokens
    DROP COLUMN IF EXISTS attempt_count;

ALTER TABLE identity_password_reset_tokens
    ADD CONSTRAINT identity_password_reset_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE identity_email_verification_tokens
    ADD CONSTRAINT identity_email_verification_tokens_token_hash_key UNIQUE (token_hash);
