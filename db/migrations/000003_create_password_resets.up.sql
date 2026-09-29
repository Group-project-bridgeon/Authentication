CREATE TABLE password_resets (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    otp_hash     TEXT NOT NULL,
    attempts     INT NOT NULL DEFAULT 0,
    expires_at   TIMESTAMPTZ NOT NULL,
    last_sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);
