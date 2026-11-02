-- Explicit migration, after 001-004. No usage/lease/revision/counter data is changed.
-- Preserve old backend metadata: legacy nodes must NOT silently become native.
START TRANSACTION;
UPDATE node SET engine='kernel' WHERE engine='iptables';
UPDATE tunnel SET engine='kernel' WHERE engine='iptables';
COMMIT;
ALTER TABLE node ALTER COLUMN kernel_backend SET DEFAULT 'nftables';
