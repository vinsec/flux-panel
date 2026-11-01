-- Explicit code rollback only, while panel/control writers are stopped.
-- Keep every ledger/lease/counter and backend identity; do not restore an old DB snapshot.
START TRANSACTION;
UPDATE node SET engine='iptables' WHERE engine='kernel';
UPDATE tunnel SET engine='iptables' WHERE engine='kernel';
COMMIT;
ALTER TABLE node ALTER COLUMN kernel_backend SET DEFAULT 'iptables';
