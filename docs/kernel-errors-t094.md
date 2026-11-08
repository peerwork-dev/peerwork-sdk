# Generic Kernel errors

Python `KernelError` subclasses `RuntimeError`; Node `KernelError` subclasses `Error`. Both expose a stable `code` and a fixed redacted message. CLI `kernel` failures emit the same `code`/`message` JSON on stderr. Argument shape errors remain Python TypeError/ValueError, Node TypeError, or CLI INPUT_INVALID/CONFIG_INVALID; they do not authorize a network operation.

Codes describe typed failures: CONFIG_INVALID, TRANSPORT_FAILED, TIMEOUT, CANCELLED, SUBMITTED_UNCERTAIN, RESOURCE_LIMIT, IDENTITY_MISSING, IDENTITY_STATE, STATE_INVALID, STATE_CONFLICT, STATE_FAILED, DISCOVERY_FAILED, DISCOVERY_CHANGED, COMMAND_INVALID, NOT_FOUND, AUTHORITY_MISMATCH, VERIFICATION_FAILED, SERVICE_REJECTED, MIGRATION_FAILED and RUNTIME_FAILED. MIGRATION_FAILED describes the migration boundary, without inferring a finer cause. Messages contain no underlying database, I/O, signer, URL, proxy, request or key text. Codes do not grant permission or select a retry policy.

Successful results and NOT_FOUND/PENDING/ACCEPTED status objects retain their existing shape. A returned pending status remains a result. SUBMITTED_UNCERTAIN and CANCELLED exceptions arise only from the existing typed error variants. The caller must retain and reconcile the original saved command; this change does not retry, regenerate, enroll or replace identities.

This adds a specific generic Kernel contract under the original common-error requirement. Prior documentation did not promise this particular exception class. Compiled-local evidence is separate from installed release-cohort acceptance.
