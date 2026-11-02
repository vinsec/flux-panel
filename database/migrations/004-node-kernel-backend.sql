-- Explicit, additive migration. Existing agents retain their historical backend.
-- New kernel nodes receive nftables through the create API, not a DB backfill.
SET @q = IF(EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='node' AND column_name='kernel_backend'),'SELECT 1',"ALTER TABLE node ADD COLUMN kernel_backend VARCHAR(16) NOT NULL DEFAULT 'iptables'");
PREPARE stmt FROM @q; EXECUTE stmt; DEALLOCATE PREPARE stmt;
