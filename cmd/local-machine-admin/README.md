# Local machine bootstrap

An explicit local operator command using the existing MachineService/repository.
No server route is added. DATABASE_URL, JWT_PRIVATE_KEY_PATH and JWT_ISSUER come
from the owning service's environment. Target flags are mandatory:

```text
auth-local-admin --local-host postgres --local-database auth_db --output-dir /protected
```

Use an absolute, existing, operator-restricted delivery directory outside every
repository/build context. Supply database secrets through the container environment,
never flags/history. This command supports `postgres` and loopback host targets only;
database and fallback-host configuration must match the explicit flags.

The existing service creates a disabled identity, installs only the fixed
catalog-stock-references / catalog.stock-references:read grant, rotates a random
256-bit 30-day credential, delivers Inventory's JSON file and enables the machine
last. Secret generation, hashing, expiry and lifecycle rules are not reimplemented.
Only non-secret receipt metadata goes to stdout. Files are created exclusively
with owner-only file modes; enforce Windows ACLs/host-bind restrictions externally.

`machine-journal.jsonl` appends and synchronizes intent before Create/Rotate calls,
so generated IDs are available even when acknowledgement is lost. Existing legacy
machine-state.json, a journal or credential blocks bootstrap. Never retry in another
directory. Reconcile identity, grant, credential and enabled status using stored IDs;
an unknown credential whose plaintext was not delivered requires reviewed recovery,
not an automatic extra rotation. No deletion, rollback or retry is performed.

The journal is a local filesystem durability measure, not a claim of power-loss
testing or a remote secret manager. Keep it and the credential protected. This is
bootstrap only; later lifecycle rotation/revocation still requires an authorized
operator process. See ERP-Platform/docs/opening-stock-local-operations.md in the
adjacent checkout for portable setup, TLS, backups, dependencies and testing.
