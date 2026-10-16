-- Intentionally retain definitions on rollback: existing role grants may use
-- them, and pre-existing resource/action rows cannot be distinguished safely.
-- Roll back Catalog code separately; permissions alone confer no access.
SELECT 1;
